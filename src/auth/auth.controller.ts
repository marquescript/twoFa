import { Body, Controller, HttpCode, Post, Req, Res, UseGuards } from "@nestjs/common";
import { Request, Response } from "express";
import { VerifyRefreshJwtGuard } from "./guards/verify-refresh-jwt.guard";
import { AuthService } from "./auth.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { LoginDto } from "./dto/login.dto";
import { EnvironmentService } from "src/config/environment/environment.service";
import { ApiBadRequestResponse, ApiBody, ApiCookieAuth, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags, ApiUnauthorizedResponse } from "@nestjs/swagger";
import { TokensResponseDto } from "./dto/tokens-response.dto";

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