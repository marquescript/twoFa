import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Request } from "express";
import { JwtService } from "../jwt.service";
import { EnvironmentService } from "src/config/environment/environment.service";
import { JwtPayload } from "../@types/express";

@Injectable()
export class VerifyJwtGuard implements CanActivate {

    constructor(
        private readonly jwtService: JwtService,
        private readonly environmentService: EnvironmentService
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest()
        const token = this.extractTokenFromHeader(request)

        if(!token) {
            throw new UnauthorizedException('Token is required')
        }

        try {
            const payload = this.jwtService.verify(token, this.environmentService.get("JWT_PUBLIC_KEY")) as JwtPayload

            request.jwtPayload = payload
        }catch(err) {
            throw new UnauthorizedException("Token invalid or expired")
        }

        return true
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}