
export interface JwtPayload {
    jti: string
    sub: string
    email: string
    iat: number
    exp: number
}

declare global {
    namespace Express {
        export interface Request {
            jwtPayload: JwtPayload
            refreshToken: string
        }
    }
}