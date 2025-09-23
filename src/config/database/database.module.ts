import { Module } from "@nestjs/common";
import { PrismaService } from "./prisma.service";
import { RedisService } from "./redis.service";
import { EnvironmentService } from "../environment/environment.service";
import { EnvironmentModule } from "../environment/environment.module";
import { LoggerModule } from "../logger/logger.module";
import { LoggerService } from "../logger/logger.service";

@Module({
    providers: [
        {
            provide: RedisService,
            inject: [EnvironmentService, LoggerService],
            useFactory: async (environmentService: EnvironmentService, logger: LoggerService) => {
                return new RedisService({
                    host: environmentService.get("REDIS_HOST"),
                    port: environmentService.get("REDIS_PORT"),
                    password: environmentService.get("REDIS_PASSWORD")
                }, logger)
            }
        },
        PrismaService
    ],
    exports: [
        PrismaService,
        RedisService
    ],
    imports: [
        EnvironmentModule,
        LoggerModule
    ]
})
export class DatabaseModule {}
