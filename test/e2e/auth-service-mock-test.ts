import { Injectable } from "@nestjs/common";
import * as crypto from "crypto";
import * as bcrypt from "bcryptjs";
import * as jwt from "jsonwebtoken";
import * as otplib from "otplib";

@Injectable()
export class AuthServiceMockTest {
    async generateBackupCodesTest() {
        const numberOfCodes = 8
        const numberOfBytesPerCode = 4
        const backupCodes: string[] = []

        for(let i = 0; i < numberOfCodes; i++) {
            const randomBytes = crypto.randomBytes(numberOfBytesPerCode)
            const code = randomBytes.toString('hex').toUpperCase()
            const formattedCode = `${code.substring(0, 4)}-${code.substring(4)}`
            backupCodes.push(formattedCode)
        }

        const hashedBackupCodes = await Promise.all(
            backupCodes.map(code => bcrypt.hash(code, 8))
        )

        return { backupCodes, hashedBackupCodes }
    }

    async generateAccessTokenTest(id: string, email: string, secret: string) {
        const accessToken = jwt.sign({ sub: id, email: email }, secret, { 
            expiresIn: "2m",
            algorithm: 'RS256'
        })

        return accessToken
    }

    async generateRefreshTokenTest(id: string, secret: string) {
        const refreshToken = jwt.sign({ sub: id, jti: crypto.randomUUID() }, secret, { 
            expiresIn: "5m",
            algorithm: 'RS256'
        })

        return refreshToken
    }

    generateValidTwoFaToken(secret: string): string {
        return otplib.authenticator.generate(secret)
    }

    getRefreshTokenFromHeaders(response: any) {
        const rawSetCookieLogin = response.headers['set-cookie']
        const loginCookies = Array.isArray(rawSetCookieLogin) ? rawSetCookieLogin : [rawSetCookieLogin as string]
        const refreshCookieLogin = loginCookies.find((c: string) => c.startsWith('refresh_token='))
        const refreshToken = (refreshCookieLogin as string).split('refresh_token=')[1].split(';')[0]
        return refreshToken
    }
}