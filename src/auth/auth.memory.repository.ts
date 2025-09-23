import { Injectable, NotFoundException } from "@nestjs/common";
import { RedisService } from "src/config/database/redis.service";

@Injectable()
export class AuthMemoryRepository {

    constructor(
        private readonly redisService: RedisService
    ) {}

    async storeRefreshToken(userId: string, refreshToken: string): Promise<void> {
        const key = this.generateKey(userId)
        const expiresIn = 60 * 60 * 24 * 7
        await this.redisService.del(key)
        await this.redisService.lpush(key, refreshToken)
        await this.redisService.expire(key, expiresIn)
    }

    async addRefreshTokenInTheExistingSession(userId: string, refreshToken: string): Promise<void> {
        const key = this.generateKey(userId)
        await this.redisService.lpush(key, refreshToken)
    }

    async getRefreshToken(userId: string): Promise<string[]> {
        const key = `session:${userId}`
        return await this.redisService.lrange(key, 0, -1)
    }

    async deleteAllRefreshToken(userId: string): Promise<void> {
        const key = this.generateKey(userId)
        await this.redisService.del(key)
    }

    async addToAccessTokenDenyList(jti: string, exp: number): Promise<void> {
        const key = `denylist_jti:${jti}`
        await this.redisService.set(key, 'revoked', 'EX', exp)
    }

    async isAccessTokenRevoked(jti: string): Promise<boolean> {
        const key = `denylist_jti:${jti}`
        const result = await this.redisService.get(key)
        return result === "revoked"
    }

    private generateKey(userId: string): string {
        return `session:${userId}`
    }
}