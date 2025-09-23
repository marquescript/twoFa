import { Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthRepository } from "./auth.repository";
import { JwtService } from "./jwt.service";
import { VerifyJwtGuard } from "./guards/verify-jwt.guard";
import { VerifyRefreshJwtGuard } from "./guards/verify-refresh-jwt.guard";
import { AuthController } from "./auth.controller";
import { DatabaseModule } from "../config/database/database.module";
import { EnvironmentModule } from "../config/environment/environment.module";
import { AuthMemoryRepository } from "./auth.memory.repository";

@Module({
    imports: [
        DatabaseModule,
        EnvironmentModule
    ],
    controllers: [
        AuthController
    ],
    providers: [
        AuthService,
        AuthRepository,
        JwtService,
        VerifyJwtGuard,
        VerifyRefreshJwtGuard,
        AuthMemoryRepository
    ],
})
export class AuthModule {}