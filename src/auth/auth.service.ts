import { ConflictException, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthRepository } from "./auth.repository";
import { CreateUserDto } from "./dto/create-user.dto";
import * as bcrypt from 'bcryptjs';
import User from "./user.model";
import { JwtService } from "./jwt.service";
import { EnvironmentService } from "src/config/environment/environment.service";
import { LoginDto } from "./dto/login.dto";
import * as otplib from "otplib";
import * as qrcode from "qrcode";
import { decrypt, encrypt } from "./utils/crypto";
import { TwoFaAuthRequiredException } from "./exceptions/two-fa-auth-required";
import * as crypto from 'crypto';
import { REFRESH_TOKEN_EXPIRATION_TIME } from "./utils/constants";
import { AuthMemoryRepository } from "./auth.memory.repository";

@Injectable()
export class AuthService {

    constructor(
        private readonly authRepository: AuthRepository,
        private readonly authMemoryRepository: AuthMemoryRepository,
        private readonly jwtService: JwtService,
        private readonly environmentService: EnvironmentService
    ) {}

    async createUser(input: CreateUserDto): Promise<{
        accessToken: string, 
        refreshToken: string
    }> {
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

        return { accessToken, refreshToken }
    }

    async login(input: LoginDto): Promise<{ 
        accessToken: string, 
        refreshToken: string 
    }> {
        const { email, password, twoFaToken, backupCode } = input

        const user = await this.authRepository.findUserByEmail(email)

        if(!user || !(await bcrypt.compare(password, user.password))) {
            throw new UnauthorizedException('Invalid credentials')
        }

        if(user.twoFaEnabled) {
            let isSecondFactorValid = false

            if(backupCode) {
                isSecondFactorValid = await this.validateAndInvalidBackupCode(user, backupCode)
                if(!isSecondFactorValid) {
                    throw new UnauthorizedException('Invalid backup code')
                }
            } else if(twoFaToken) {
                isSecondFactorValid = await this.verifyTwoFa(user, twoFaToken)
                if(!isSecondFactorValid) {
                    throw new UnauthorizedException('Invalid two factor authentication token')
                }
            } else {
                throw new TwoFaAuthRequiredException()
            }
        }
        
        const accessToken = this.generateAccessToken({
            id: user.id,
            email: user.email,
        })

        const refreshToken = this.generateRefreshToken({ id: user.id })

        await this.authMemoryRepository.storeRefreshToken(user.id, refreshToken)

        return { accessToken, refreshToken }
    }

    async refreshTokens(userId: string, refreshToken: string): Promise<{ 
        accessToken: string, 
        refreshToken: string 
    }> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            throw new UnauthorizedException('User not found')
        }

        await this.validateRefreshToken(userId, refreshToken)

        const accessToken = this.generateAccessToken({
            id: user.id,
            email: user.email,
        })

        const newRefreshToken = this.generateRefreshToken({ id: user.id })

        await this.authMemoryRepository.addRefreshTokenInTheExistingSession(userId, newRefreshToken)

        return { accessToken, refreshToken: newRefreshToken }
    }

    async enableTwoFa(userId: string) {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
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

        return await qrcode.toDataURL(otpAuth)
    }

    async confirmTwoFa(userId: string, token: string): Promise<string[]> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            throw new UnauthorizedException('User not found')
        }

        if(!user.twoFaSecret) {
            throw new UnauthorizedException('Two factor authentication is not initialized')
        }

        const isValid = await this.verifyTwoFa(user, token)

        if(!isValid) {
            throw new UnauthorizedException('Invalid two factor authentication token')
        }

        await this.authRepository.setTwoFaAsEnabled(user.id)

        const backupCodes = this.generateBackupCodes()

        const hashedBackupCodes = await Promise.all(
            backupCodes.map(code => bcrypt.hash(code, 8))
        )

        await this.authRepository.saveBackupCodes(user.id, hashedBackupCodes)

        return backupCodes
    }

    async verifyTwoFa(user: User, token: string): Promise<boolean> {
        if(!user.twoFaSecret) {
            throw new UnauthorizedException('Two factor authentication is not enabled')
        }

        const decryptedSecret = decrypt(user.twoFaSecret, this.environmentService.get("ENCRYPTION_KEY"))

        return otplib.authenticator.verify({ token, secret: decryptedSecret })
    }

    async disableTwoFa(userId: string): Promise<void> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            throw new UnauthorizedException('User not found')
        }

        if(!user.twoFaEnabled) {
            throw new UnauthorizedException('Two factor authentication is not enabled')
        }

        await this.authRepository.disableTwoFa(user.id)
    }

    async logout(userId: string, jti: string, exp: number): Promise<void> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
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
        const payload = {
            sub: user.id,
            email: user.email,
            jti: crypto.randomUUID()
        }
        
        const token = this.jwtService.sign(payload, this.environmentService.get("JWT_PRIVATE_KEY"), { 
            expiresIn: '15m',
            algorithm: 'RS256'
        })
        return token
    }

    private generateRefreshToken(user: Partial<User>) {
        const payload = {
            sub: user.id,
            jti: crypto.randomUUID()
        }
        
        const token = this.jwtService.sign(payload, this.environmentService.get("JWT_PRIVATE_KEY"), { 
            expiresIn: REFRESH_TOKEN_EXPIRATION_TIME,
            algorithm: 'RS256'
        })
        return token
    }

    private async validateRefreshToken(userId: string, refreshToken: string) {
        const refreshTokens = await this.authMemoryRepository.getRefreshToken(userId)

        if(refreshTokens.length === 0) {
            throw new UnauthorizedException("Session not found or expired")
        }

        const latestValidRefreshToken = refreshTokens[0]
        const tokenExistsInSession = refreshTokens.includes(refreshToken)

        if(!tokenExistsInSession || refreshToken !== latestValidRefreshToken) {
            await this.authMemoryRepository.deleteAllRefreshToken(userId)
            throw new UnauthorizedException("Invalid refresh token")
        }
    }
}