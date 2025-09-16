import { Body, Controller, Get, HttpCode, Post, Req, Res, UseGuards } from "@nestjs/common";
import { Request, Response } from "express";
import { VerifyRefreshJwtGuard } from "./guards/verify-refresh-jwt.guard";
import { AuthService } from "./auth.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { LoginDto } from "./dto/login.dto";
import { EnvironmentService } from "src/config/environment/environment.service";

@Controller("auth")
export class AuthController {

    constructor(
        private readonly authService: AuthService,
        private readonly environmentService: EnvironmentService
    ) {}

    @Post("register")
    @HttpCode(201)
    async register(@Body() request: CreateUserDto, @Res({ passthrough: true }) response: Response) {
        const { accessToken, refreshToken } = await this.authService.createUser(request)
        this.setRefreshToken(response, refreshToken)
        return { accessToken }
    }

    @Post("login")
    @HttpCode(200)
    async login(@Body() request: LoginDto, @Res({ passthrough: true }) response: Response) {
        const { accessToken, refreshToken } = await this.authService.login(request)
        this.setRefreshToken(response, refreshToken)
        return { accessToken }
    }

    @Post("refresh")
    @HttpCode(200)
    @UseGuards(VerifyRefreshJwtGuard)
    async refrehToken(@Req() request: Request, @Res({ passthrough: true }) response: Response) {
        const { sub } = request.jwtPayload
        const { accessToken, refreshToken } = await this.authService.refreshTokens(sub)
        this.setRefreshToken(response, refreshToken)
        return { accessToken: accessToken }
    }

    private setRefreshToken(response: Response,refreshToken: string) {
        response.cookie("refresh_token", refreshToken, {
            httpOnly: true,
            secure: this.environmentService.get("NODE_ENV") !== "development",
            sameSite: "strict",
            path: "/auth/refresh",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
    }
}