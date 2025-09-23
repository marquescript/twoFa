import { Injectable } from "@nestjs/common";
import * as jwt from 'jsonwebtoken';

@Injectable()
export class JwtService {

    sign(paylaod: Object, key: string, options: jwt.SignOptions = {}) {
        return jwt.sign(paylaod, key, options)
    }

    verify(token: string, key: string) {
        return jwt.verify(token, key)
    }

    decode(token: string) {
        return jwt.decode(token)
    }
}