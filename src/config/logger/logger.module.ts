import { Module } from "@nestjs/common";
import { LoggerService } from "./logger.service";
import { RequestStorageService } from "./request-storage.service";

@Module({
    providers: [
        LoggerService,
        RequestStorageService
    ],
    exports: [
        LoggerService
    ]
})
export class LoggerModule {}