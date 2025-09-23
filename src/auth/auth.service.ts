import { ConflictException, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthRepository } from "./auth.repository";
import { CreateUserDto } from "./dto/create-user.dto";
import * as bcrypt from 'bcryptjs';
import User from "./user.model";
import { JwtService } from "./jwt.service";
import { EnvironmentService } from "src/config/environment/environment.service";
import { CompleteTwoFactorDto, InitialLoginDto } from "./dto/login.dto";
import * as otplib from "otplib";
import * as qrcode from "qrcode";
import { decrypt, encrypt } from "./utils/crypto";
import { TwoFaAuthRequiredException } from "./exceptions/two-fa-auth-required";
import * as crypto from 'crypto';
import { REFRESH_TOKEN_EXPIRATION_TIME } from "./utils/constants";
import { AuthMemoryRepository } from "./auth.memory.repository";
import { LoggerService } from "src/config/logger/logger.service";
import { JwtPayload } from "./@types/express";

type AuthenticationType = "backupCode" | "twoFaToken" | "default"

@Injectable()
export class AuthService {

    constructor(
        private readonly authRepository: AuthRepository,
        private readonly authMemoryRepository: AuthMemoryRepository,
        private readonly jwtService: JwtService,
        private readonly environmentService: EnvironmentService,
        private readonly logger: LoggerService
    ) {
        this.logger.setContext("auth.service")
    }

    async createUser(input: CreateUserDto): Promise<{
        accessToken: string, 
        refreshToken: string
    }> {
        this.logger.log("Creating user", { email: input.email, name: input.name })
        const { email, name, password } = input

        const isEmailExists = await this.authRepository.findUserByEmail(email)

        if(isEmailExists) {
            throw new ConflictException('Email already exists')
        }

        const passwordHash = await bcrypt.hash(password, 8)

        const user = new User({
            email,
            name,
            password: passwordHash
        })

        const userCreated = await this.authRepository.createUser(user)

        const accessToken = this.generateAccessToken({
            id: userCreated.id,
            email: userCreated.email,
        })

        const refreshToken = this.generateRefreshToken({ id: userCreated.id })

        await this.authMemoryRepository.storeRefreshToken(userCreated.id, refreshToken)

        this.logger.log("User created", { email: userCreated.email, name: userCreated.name })

        return { accessToken, refreshToken }
    }

    async initiateLogin(input: InitialLoginDto): Promise<{
        accessToken: string, 
        refreshToken: string 
    }> {
        this.logger.log("Initiating login", { email: input.email })

        const { email, password } = input

        const user = await this.authRepository.findUserByEmail(email)

        if(!user || !(await bcrypt.compare(password, user.password))) {
            this.logger.warn("Invalid credentials", { email: input.email })
            throw new UnauthorizedException('Invalid credentials')
        }

        if(!user.twoFaEnabled) {
            this.logger.log("Login successful (2FA disabled)", { userId: user.id });

            return this.grantFinalTokens(user.id, user.email, "default")
        }

        const temporaryToken = this.generateTokenToReLoginWithTwoFactorToken(user.id)
        this.logger.warn("2FA enabled, redirecting to complete two factor authentication", { userId: user.id })
        throw new TwoFaAuthRequiredException(temporaryToken)
    }

    async completeTwoFactorlogin(input: CompleteTwoFactorDto): Promise<{ 
        accessToken: string, 
        refreshToken: string 
    }> {
        const { twoFaToken, backupCode, temporaryToken } = input

        let payload: JwtPayload

        try{
            payload = this.jwtService.verify(temporaryToken, this.environmentService.get("JWT_PUBLIC_KEY")) as JwtPayload
            
            if(payload.purpose !== "2fa-verification") {
                this.logger.warn("Invalid temporary token", { userId: payload.sub })
                throw new UnauthorizedException('Invalid token purpose')
            }
        }catch(err) {
            this.logger.warn("Invalid or expired temporary token")
            throw new UnauthorizedException('Invalid or expired temporary token')
        }

        const userId = payload.sub

        const user = await this.authRepository.findUserById(userId)
        if(!user) {
            this.logger.warn("User not found", { userId })
            throw new UnauthorizedException('User not found')
        }

        let typeAuthentication: AuthenticationType

        let isSecondFactorValid = false
        if(backupCode) {
            isSecondFactorValid = await this.validateAndInvalidBackupCode(user, backupCode)
            if(!isSecondFactorValid) {
                this.logger.warn("Invalid backup code", { userId: user.id })
                throw new UnauthorizedException('Invalid backup code')
            }
            typeAuthentication = "backupCode"
        } else if(twoFaToken) {
            isSecondFactorValid = await this.verifyTwoFa(user, twoFaToken)
            if(!isSecondFactorValid) {
                this.logger.warn("Invalid two factor authentication token", { userId: user.id })
                throw new UnauthorizedException('Invalid two factor authentication token')
            }
            typeAuthentication = "twoFaToken"
        } else {
            throw new UnauthorizedException('Two factor authentication token or backup code is required')
        }

        return this.grantFinalTokens(user.id, user.email, typeAuthentication)
    }

    async refreshTokens(userId: string, refreshToken: string): Promise<{ 
        accessToken: string, 
        refreshToken: string 
    }> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            this.logger.warn("User not found", { userId })
            throw new UnauthorizedException('User not found')
        }

        await this.validateRefreshToken(userId, refreshToken)

        const accessToken = this.generateAccessToken({
            id: user.id,
            email: user.email,
        })

        const newRefreshToken = this.generateRefreshToken({ id: user.id })

        await this.authMemoryRepository.addRefreshTokenInTheExistingSession(userId, newRefreshToken)

        this.logger.log("Refresh token rotated", { userId })
        return { accessToken, refreshToken: newRefreshToken }
    }

    async enableTwoFa(userId: string) {
        this.logger.log("Enabling two factor authentication", { userId })

        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            this.logger.warn("User not found", { userId })
            throw new UnauthorizedException('User not found')
        }

        const secret = otplib.authenticator.generateSecret()

        const encryptedSecret = encrypt(secret, this.environmentService.get("ENCRYPTION_KEY"))

        await this.authRepository.saveTwoFaSecret(userId, encryptedSecret)

        const otpAuth = otplib.authenticator.keyuri(
            userId, 
            this.environmentService.get("TWOFA_APP_NAME"), 
            secret
        )

        this.logger.log("Two factor authentication enabled", { userId })

        return await qrcode.toDataURL(otpAuth)
    }

    async confirmTwoFa(userId: string, token: string): Promise<string[]> {
        this.logger.log("Confirming two factor authentication", { userId })

        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            this.logger.warn("User not found", { userId })
            throw new UnauthorizedException('User not found')
        }

        if(!user.twoFaSecret) {
            this.logger.warn("Two factor authentication is not initialized", { userId })
            throw new UnauthorizedException('Two factor authentication is not initialized')
        }

        const isValid = await this.verifyTwoFa(user, token)

        if(!isValid) {
            this.logger.warn("Invalid two factor authentication token", { userId })
            throw new UnauthorizedException('Invalid two factor authentication token')
        }

        await this.authRepository.setTwoFaAsEnabled(user.id)

        const backupCodes = this.generateBackupCodes()

        const hashedBackupCodes = await Promise.all(
            backupCodes.map(code => bcrypt.hash(code, 8))
        )

        await this.authRepository.saveBackupCodes(user.id, hashedBackupCodes)

        this.logger.log("Two factor authentication confirmed", { userId })

        return backupCodes
    }

    private async verifyTwoFa(user: User, token: string): Promise<boolean> {
        this.logger.debug("Verifying two factor authentication", { userId: user.id })

        if(!user.twoFaSecret) {
            this.logger.warn("Two factor authentication is not enabled", { userId: user.id })
            throw new UnauthorizedException('Two factor authentication is not enabled')
        }

        const decryptedSecret = decrypt(user.twoFaSecret, this.environmentService.get("ENCRYPTION_KEY"))

        return otplib.authenticator.verify({ token, secret: decryptedSecret })
    }

    async disableTwoFa(userId: string): Promise<void> {
        this.logger.log("Disabling two factor authentication", { userId })

        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            this.logger.warn("User not found", { userId })
            throw new UnauthorizedException('User not found')
        }

        if(!user.twoFaEnabled) {
            this.logger.warn("Two factor authentication is not enabled", { userId: user.id })
            throw new UnauthorizedException('Two factor authentication is not enabled')
        }

        await this.authRepository.disableTwoFa(user.id)

        this.logger.log("Two factor authentication disabled", { userId })
    }

    async logout(userId: string, jti: string, exp: number): Promise<void> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            this.logger.warn("User not found", { userId })
            throw new UnauthorizedException('User not found')
        }

        const currentTimeInSeconds = Math.floor(Date.now() / 1000)
        const remainingTime = exp - currentTimeInSeconds

        if(remainingTime > 0) {
            await this.authMemoryRepository.addToAccessTokenDenyList(jti, remainingTime)
        }

        await this.authMemoryRepository.deleteAllRefreshToken(userId)
    }

    private async validateAndInvalidBackupCode(
        user: User,
        backupCode: string
    ): Promise<boolean> {
        this.logger.debug("Validating and invalid backup code", { userId: user.id })
        
        const currentHashes = user.backupCodes
        let matchingHash: string | null = null

        for(const hash of currentHashes) {
            const isMatch = await bcrypt.compare(backupCode, hash)
            if(isMatch) {
                matchingHash = hash
                break
            }
        }

        if(matchingHash) {
            const updatedHashes = currentHashes.filter(hash => hash !== matchingHash)
            await this.authRepository.saveBackupCodes(user.id, updatedHashes)
            return true
        }

        return false
    }

    private generateBackupCodes() {
        this.logger.debug("Generating backup codes")
        
        const numberOfCodes = 8
        const numberOfBytesPerCode = 4
        const backupCodes: string[] = []

        for(let i = 0; i < numberOfCodes; i++) {
            const randomBytes = crypto.randomBytes(numberOfBytesPerCode)
            const code = randomBytes.toString('hex').toUpperCase()
            const formattedCode = `${code.substring(0, 4)}-${code.substring(4)}`
            backupCodes.push(formattedCode)
        }

        return backupCodes
    }

    private generateAccessToken(user: Partial<User>) {
        this.logger.debug("Generating access token", { userId: user.id })
        
        const payload = {
            sub: user.id,
            email: user.email,
            jti: crypto.randomUUID(),
            purpose: "access"
        }
        
        const token = this.jwtService.sign(payload, this.environmentService.get("JWT_PRIVATE_KEY"), { 
            expiresIn: '15m',
            algorithm: 'RS256'
        })
        return token
    }

    private generateRefreshToken(user: Partial<User>) {
        this.logger.debug("Generating refresh token", { userId: user.id })
        
        const payload = {
            sub: user.id,
            jti: crypto.randomUUID(),
            purpose: "refresh"
        }
        
        const token = this.jwtService.sign(payload, this.environmentService.get("JWT_PRIVATE_KEY"), { 
            expiresIn: REFRESH_TOKEN_EXPIRATION_TIME,
            algorithm: 'RS256'
        })
        return token
    }

    private async validateRefreshToken(userId: string, refreshToken: string) {
        this.logger.debug("Validating refresh token", { userId })
        
        const refreshTokens = await this.authMemoryRepository.getRefreshToken(userId)

        if(refreshTokens.length === 0) {
            this.logger.warn("Session not found or expired", { userId })
            throw new UnauthorizedException("Session not found or expired")
        }

        const latestValidRefreshToken = refreshTokens[0]
        const tokenExistsInSession = refreshTokens.includes(refreshToken)

        if(!tokenExistsInSession || refreshToken !== latestValidRefreshToken) {
            await this.authMemoryRepository.deleteAllRefreshToken(userId)
            this.logger.warn("Invalid refresh token", { userId })
            throw new UnauthorizedException("Invalid refresh token")
        }
    }

    private generateTokenToReLoginWithTwoFactorToken(userId: string) {
        this.logger.debug("Generating token to re-login with two factor token")

        const payload = {
            sub: userId,
            purpose: "2fa-verification"
        }

        const token = this.jwtService.sign(
            payload, this.environmentService.get("JWT_PRIVATE_KEY"), { expiresIn: "3m", algorithm: "RS256" }
        )

        return token
    }

    private async grantFinalTokens(userId: string, email: string, typeAuthentication: AuthenticationType):  Promise<{
        accessToken: string,
        refreshToken: string
    }> {
        const accessToken = this.generateAccessToken({
            id: userId,
            email: email,
        })

        const refreshToken = this.generateRefreshToken({ id: userId })

        await this.authMemoryRepository.storeRefreshToken(userId, refreshToken)

        this.logger.log("Login successful", { userId: userId, typeAuthentication })

        return { accessToken, refreshToken }
    }
}