import { Module } from "@nestjs/common";
import { EnvironmentService } from "./environment.service";
import { ConfigModule } from "@nestjs/config";
import { plainToInstance } from "class-transformer";
import { validateSync } from "class-validator";
import { Environment } from "./environment";

@Module({
    imports: [ConfigModule.forRoot({
        isGlobal: true,
        validate: (config: Record<string, unknown>) => {
            const validated = plainToInstance(Environment, config, { enableImplicitConversion: true });
            const errors = validateSync(validated, { whitelist: true, forbidUnknownValues: false });
            if (errors.length) {
                throw new Error(`Invalid environment variables: ${errors.map(e => Object.values(e.constraints || {}).join(", ")).join("; ")}`);
            }
            return validated as unknown as Record<string, unknown>;
        }
    })],
    providers: [EnvironmentService],
    exports: [EnvironmentService]
})
export class EnvironmentModule {}