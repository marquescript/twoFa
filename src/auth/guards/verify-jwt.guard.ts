import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Request } from "express";
import { JwtService } from "../jwt.service";
import { EnvironmentService } from "src/config/environment/environment.service";
import { JwtPayload } from "../@types/express";
import { AuthMemoryRepository } from "../auth.memory.repository";

@Injectable()
export class VerifyJwtGuard implements CanActivate {

    constructor(
        private readonly jwtService: JwtService,
        private readonly environmentService: EnvironmentService,
        private readonly authMemoryRepository: AuthMemoryRepository
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest()
        const token = this.extractTokenFromHeader(request)

        if(!token) {
            throw new UnauthorizedException('Token is required')
        }

        try {            
            const payload = this.jwtService.verify(token, this.environmentService.get("JWT_PUBLIC_KEY")) as JwtPayload

            if(payload.purpose !== "access") {
                throw new UnauthorizedException("Token invalid")
            }

            const jti = payload.jti
            if(jti) {
                const isRevoked = await this.authMemoryRepository.isAccessTokenRevoked(jti)
                if(isRevoked) {
                    throw new UnauthorizedException("Token invalid or expired")
                }
            }

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