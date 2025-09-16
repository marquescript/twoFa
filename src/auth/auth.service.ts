import { ConflictException, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthRepository } from "./auth.repository";
import { CreateUserDto } from "./dto/create-user.dto";
import * as bcrypt from 'bcryptjs';
import User from "./user.model";
import { JwtService } from "./jwt.service";
import { EnvironmentService } from "src/config/environment/environment.service";
import { LoginDto } from "./dto/login.dto";

@Injectable()
export class AuthService {

    constructor(
        private readonly authRepository: AuthRepository,
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

        return { accessToken, refreshToken }
    }

    async login(input: LoginDto): Promise<{ 
        accessToken: string, 
        refreshToken: string 
    }> {
        const { email, password } = input

        const user = await this.authRepository.findUserByEmail(email)

        if(!user || !(await bcrypt.compare(password, user.password))) {
            throw new UnauthorizedException('Invalid credentials')
        }

        const accessToken = this.generateAccessToken({
            id: user.id,
            email: user.email,
        })

        const refreshToken = this.generateRefreshToken({ id: user.id })

        return { accessToken, refreshToken }
    }

    async refreshTokens(userId: string): Promise<{ 
        accessToken: string, 
        refreshToken: string 
    }> {
        const user = await this.authRepository.findUserById(userId)

        if(!user) {
            throw new UnauthorizedException('User not found')
        }

        const accessToken = this.generateAccessToken({
            id: user.id,
            email: user.email,
        })

        const refreshToken = this.generateRefreshToken({ id: user.id })

        return { accessToken, refreshToken }
    }

    private generateAccessToken(user: Partial<User>) {
        const payload = {
            sub: user.id,
            email: user.email,
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
        }
        
        const token = this.jwtService.sign(payload, this.environmentService.get("JWT_PRIVATE_KEY"), { 
            expiresIn: '7d',
            algorithm: 'RS256'
        })
        return token
    }
}