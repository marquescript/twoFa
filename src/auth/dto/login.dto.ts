import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

export class InitialLoginDto {

    @ApiProperty({ example: "john.doe@email.com" })
    @IsEmail()
    email: string

    @ApiProperty({ example: "strongPassword123" })
    @IsString()
    @IsNotEmpty()
    password: string

}

export class CompleteTwoFactorDto {

    @ApiProperty({ example: "123456" })
    @IsString()
    @IsOptional()
    twoFaToken?: string

    @ApiProperty({ example: "123456" })
    @IsString()
    @IsOptional()
    backupCode?: string

    @ApiProperty({ example: "123456" })
    @IsString()
    @IsOptional()
    temporaryToken: string

}