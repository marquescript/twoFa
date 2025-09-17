import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator"
import { ApiProperty } from "@nestjs/swagger"

export class CreateUserDto {

    @ApiProperty({ example: "john.doe@email.com" })
    @IsEmail()
    email: string

    @ApiProperty({ example: "John Doe" })
    @IsString()
    @IsNotEmpty()
    name: string

    @ApiProperty({ example: "strongPassword123", minLength: 6 })
    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    password: string

}