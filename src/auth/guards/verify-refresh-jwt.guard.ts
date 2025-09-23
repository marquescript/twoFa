import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Request } from "express";
import { JwtService } from "../jwt.service";
import { EnvironmentService } from "src/config/environment/environment.service";
import { JwtPayload } from "../@types/express";

@Injectable()
export class VerifyRefreshJwtGuard implements CanActivate {

    constructor(
        private readonly jwtService: JwtService,
        private readonly environmentService: EnvironmentService
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>()

        const token = request.cookies?.["refresh_token"]

        if(!token) {
            throw new UnauthorizedException("Refresh token is required")
        }

        try {
            const payload = this.jwtService.verify(token, this.environmentService.get("JWT_PUBLIC_KEY")) as JwtPayload

            if(payload.purpose !== "refresh") {
                throw new UnauthorizedException("Refresh token invalid")
            }

            request.jwtPayload = payload
            request.refreshToken = token
        }catch(err) {
            throw new UnauthorizedException("Refresh token invalid or expired")
        }

        return true
    }
}