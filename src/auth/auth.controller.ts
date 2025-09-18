import { Body, Controller, HttpCode, Param, Post, Req, Res, UseGuards } from "@nestjs/common";
import { Request, Response } from "express";
import { VerifyRefreshJwtGuard } from "./guards/verify-refresh-jwt.guard";
import { AuthService } from "./auth.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { LoginDto } from "./dto/login.dto";
import { EnvironmentService } from "src/config/environment/environment.service";
import { ApiBadRequestResponse, ApiBody, ApiCookieAuth, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags, ApiUnauthorizedResponse } from "@nestjs/swagger";
import { TokensResponseDto } from "./dto/tokens-response.dto";
import { VerifyJwtGuard } from "./guards/verify-jwt.guard";

@ApiTags("Auth")
@Controller("auth")
export class AuthController {

    constructor(
        private readonly authService: AuthService,
        private readonly environmentService: EnvironmentService
    ) {}

    @Post("register")
    @HttpCode(201)
    @ApiOperation({ summary: "Register a new user" })
    @ApiCreatedResponse({ description: "User created", type: TokensResponseDto })
    @ApiBadRequestResponse({ description: "Invalid data" })
    @ApiBody({ type: CreateUserDto })
    async register(@Body() request: CreateUserDto, @Res({ passthrough: true }) response: Response) {
        const { accessToken, refreshToken } = await this.authService.createUser(request)
        this.setRefreshToken(response, refreshToken)
        return { accessToken }
    }

    @Post("login")
    @HttpCode(200)
    @ApiOperation({ summary: "Authenticate a user" })
    @ApiOkResponse({ description: "Login successful", type: TokensResponseDto })
    @ApiUnauthorizedResponse({ description: "Invalid credentials" })
    @ApiBody({ type: LoginDto })
    async login(@Body() request: LoginDto, @Res({ passthrough: true }) response: Response) {
        const { accessToken, refreshToken } = await this.authService.login(request)
        this.setRefreshToken(response, refreshToken)
        return { accessToken }
    }

    @Post("refresh")
    @HttpCode(200)
    @UseGuards(VerifyRefreshJwtGuard)
    @ApiOperation({ summary: "Refresh tokens using refresh token" })
    @ApiOkResponse({ description: "Tokens refreshed", type: TokensResponseDto })
    @ApiCookieAuth("refresh_token")
    async refrehToken(@Req() request: Request, @Res({ passthrough: true }) response: Response) {
        const { sub } = request.jwtPayload
        const { accessToken, refreshToken } = await this.authService.refreshTokens(sub)
        this.setRefreshToken(response, refreshToken)
        return { accessToken: accessToken }
    }

    @Post("enable-two-fa")
    @HttpCode(200)
    @UseGuards(VerifyJwtGuard)
    @ApiOperation({ summary: "Enable two factor authentication" })
    @ApiOkResponse({ description: "Two factor authentication enabled", type: String })
    async enableTwoFa(@Req() request: Request) {
        const { sub } = request.jwtPayload

        const qrcode = await this.authService.enableTwoFa(sub)
        return `
            <img src=${qrcode} />
        `
    }

    @Post("confirm-two-fa")
    @HttpCode(200)
    @UseGuards(VerifyJwtGuard)
    @ApiOperation({ summary: "Confirm two factor authentication" })
    @ApiOkResponse({ 
        description: "Two factor authentication confirmed", 
        type: String, 
        isArray: true, 
        example: ["1234-5678", "8765-4321"] 
    })
    @ApiBody({ schema: { type: 'object', properties: { token: { type: 'string' } } } })
    async confirmTwoFa(@Req() request: Request, @Body() body: { token: string }) {
        const { sub } = request.jwtPayload
        const backupCodes = await this.authService.confirmTwoFa(sub, body.token)
        
        return { backupCodes }
    }

    @Post("disable-two-fa")
    @HttpCode(200)
    @UseGuards(VerifyJwtGuard)
    @ApiOperation({ summary: "Disable two factor authentication" })
    @ApiOkResponse({ description: "Two factor authentication disabled" })
    async disableTwoFa(@Req() request: Request) {
        const { sub } = request.jwtPayload
        await this.authService.disableTwoFa(sub)
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