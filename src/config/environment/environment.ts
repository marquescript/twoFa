import { IsEnum, IsNotEmpty, IsString } from "class-validator";

export class Environment {

    @IsString()
    @IsNotEmpty()
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

}