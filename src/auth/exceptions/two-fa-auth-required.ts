import { UnauthorizedException } from "@nestjs/common";

export class TwoFaAuthRequiredException extends UnauthorizedException {
    constructor(){
        super({
            statusCode: 401,
            message: "Two factor authentication is required",
            errorCode: "2FA_REQUIRED"
        })
    }
}