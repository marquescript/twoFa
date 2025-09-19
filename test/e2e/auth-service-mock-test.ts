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
            expiresIn: "15m",
            algorithm: 'RS256'
        })

        return accessToken
    }

    generateValidTwoFaToken(secret: string): string {
        return otplib.authenticator.generate(secret)
    }
}