import { Injectable, Scope } from "@nestjs/common";
import pino, { levels } from "pino";
import { RequestStorageService } from "./request-storage.service";

const pinoLogger = pino({
    level: process.env.NODE_ENV === "develop" ? "debug" : "info",
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
        level: (label) => {
            return { level: label }
        }
    }
})

@Injectable({ scope: Scope.TRANSIENT })
export class LoggerService {

    private context: string = ""

    constructor(
        private readonly requestStorage: RequestStorageService
    ) {}

    setContext(context: string) {
        this.context = context
    }

    log(message: any, data?: any, context?: string) {
        const logContext = context || this.context
        const correlationId = this.requestStorage.getCorrelationId()

        pinoLogger.info({
            context: logContext,
            correlationId,
            data
        }, message)
    }

    error(message: any, data?: any, context?: string) {
        const logContext = context || this.context
        const correlationId = this.requestStorage.getCorrelationId()

        pinoLogger.error({
            context: logContext,
            correlationId,
            data
        }, message)
    }

    debug(message: any, data?: any, context?: string) {
        const logContext = context || this.context
        const correlationId = this.requestStorage.getCorrelationId()

        pinoLogger.debug({
            context: logContext,
            correlationId,
            data
        }, message)
    }

    warn(message: any, data?: any, context?: string) {
        const logContext = context || this.context
        const correlationId = this.requestStorage.getCorrelationId()

        pinoLogger.warn({
            context: logContext,
            correlationId,
            data
        }, message)
    }
}