import { Injectable } from "@nestjs/common";
import Redis, { RedisOptions } from "ioredis";

@Injectable()
export class RedisService extends Redis {

    constructor(options: RedisOptions) {
        super(options)

        super.on("error", (err) => {
            console.error("Redis error", err)
            process.exit(1)
        })

        super.on("connect", () => {
            console.log("Redis connected")
        })
    }
}