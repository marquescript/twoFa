import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

export class LoginDto {

    @ApiProperty({ example: "john.doe@email.com" })
    @IsEmail()
    email: string

    @ApiProperty({ example: "strongPassword123" })
    @IsString()
    @IsNotEmpty()
    password: string

    @ApiProperty({ example: "123456" })
    @IsString()
    @IsOptional()
    twoFaToken?: string

    @ApiProperty({ example: "123456" })
    @IsString()
    @IsOptional()
    backupCode?: string

}