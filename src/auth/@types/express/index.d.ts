
export interface JwtPayload {
    jti: string
    sub: string
    email: string
    iat: number
    exp: number
    purpose: "refresh" | "2fa-verification" | "access"
}

declare global {
    namespace Express {
        export interface Request {
            jwtPayload: JwtPayload
            refreshToken: string
        }
    }
}