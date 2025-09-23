import { Module } from "@nestjs/common";
import { PrismaService } from "./prisma.service";
import { RedisService } from "./redis.service";
import { EnvironmentService } from "../environment/environment.service";
import { EnvironmentModule } from "../environment/environment.module";

@Module({
    providers: [
        {
            provide: RedisService,
            inject: [EnvironmentService],
            useFactory: async (environmentService: EnvironmentService) => {
                return new RedisService({
                    host: environmentService.get("REDIS_HOST"),
                    port: environmentService.get("REDIS_PORT"),
                    password: environmentService.get("REDIS_PASSWORD")
                })
            }
        },
        PrismaService
    ],
    exports: [
        PrismaService,
        RedisService
    ],
    imports: [
        EnvironmentModule
    ]
})
export class DatabaseModule {}
