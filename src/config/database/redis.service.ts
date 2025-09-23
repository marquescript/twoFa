import { Injectable } from "@nestjs/common";
import Redis, { RedisOptions } from "ioredis";
import { LoggerService } from "../logger/logger.service";

@Injectable()
export class RedisService extends Redis {

    constructor(
        options: RedisOptions,
        private readonly logger: LoggerService
    ) {
        super(options)

        super.on("error", (err) => {
            this.logger.error("Redis error", err)
            process.exit(1)
        })

        super.on("connect", () => {
            this.logger.log("Redis connected")
        })
    }
}