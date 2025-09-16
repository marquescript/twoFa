import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Environment } from "./environment";

@Injectable()
export class EnvironmentService {

    constructor(private readonly configService: ConfigService<Environment, true>) {}

    get<T extends keyof Environment>(key: T) {
        return this.configService.get(key, { infer: true })
    }
}