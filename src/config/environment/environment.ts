import { IsNotEmpty, IsString } from "class-validator";

export class Environment {

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