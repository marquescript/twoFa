import { Module } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { LoggerInterceptor } from "./logger.interceptor";
import { LoggerModule } from "src/config/logger/logger.module";
import { LoggerErrorInterceptor } from "./logger-error.interceptor";

@Module({
    providers: [
        { provide: APP_INTERCEPTOR, useClass: LoggerInterceptor },
        { provide: APP_INTERCEPTOR, useClass: LoggerErrorInterceptor }
    ],
    exports: [],
    imports: [
        LoggerModule
    ]
})
export class InterceptorModule {}