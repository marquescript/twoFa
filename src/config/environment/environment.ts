import { IsEnum, IsNotEmpty, IsNumber, IsString } from "class-validator";

export class Environment {

    @IsEnum({
        values: ["development", "production"],
        default: "development"
    })
    NODE_ENV: "development" | "production"

    @IsString()
    @IsNotEmpty()
    DATABASE_URL: string

    @IsString()
    @IsNotEmpty()
    JWT_PRIVATE_KEY: string

    @IsString()
    @IsNotEmpty()
    JWT_PUBLIC_KEY: string

    @IsNumber()
    @IsNotEmpty()
    PORT: number

    @IsString()
    @IsNotEmpty()
    TWOFA_APP_NAME: string

    @IsString()
    @IsNotEmpty()
    ENCRYPTION_KEY: string

    @IsString()
    @IsNotEmpty()
    REDIS_HOST: string

    @IsNumber()
    @IsNotEmpty()
    REDIS_PORT: number

    @IsString()
    @IsNotEmpty()
    REDIS_PASSWORD: string

}