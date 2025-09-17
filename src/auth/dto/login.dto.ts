import { IsEmail, IsNotEmpty, IsString } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

export class LoginDto {

    @ApiProperty({ example: "john.doe@email.com" })
    @IsEmail()
    email: string

    @ApiProperty({ example: "strongPassword123" })
    @IsString()
    @IsNotEmpty()
    password: string

}