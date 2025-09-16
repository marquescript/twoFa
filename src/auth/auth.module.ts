import { Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthRepository } from "./auth.repository";
import { JwtService } from "./jwt.service";
import { VerifyJwtGuard } from "./guards/verify-jwt.guard";
import { VerifyRefreshJwtGuard } from "./guards/verify-refresh-jwt.guard";
import { AuthController } from "./auth.controller";
import { DatabaseModule } from "../config/database/database.module";

@Module({
    imports: [
        DatabaseModule
    ],
    controllers: [
        AuthController
    ],
    providers: [
        AuthService,
        AuthRepository,
        JwtService,
        VerifyJwtGuard,
        VerifyRefreshJwtGuard
    ],
})
export class AuthModule {}