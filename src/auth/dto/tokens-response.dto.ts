import { ApiProperty } from "@nestjs/swagger"

export class TokensResponseDto {

    @ApiProperty({ example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." })
    accessToken: string
}


