import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { LoggerService } from "src/config/logger/logger.service";
import { Observable, tap } from "rxjs";

@Injectable()
export class LoggerInterceptor implements NestInterceptor {
    
    constructor(
        private readonly logger: LoggerService
    ) {}

    intercept(context: ExecutionContext, next: CallHandler<any>): Observable<any> | Promise<Observable<any>> {
        this.logger.setContext("HTTP")

        if(context.getType() === "http") {
            const request = context.switchToHttp().getRequest()

            const { method, originalUrl, ip } = request
            const userAgent = request.get("user-agent") || ""

            this.logger.log(`'Request | ${method} ${originalUrl} - ${ip} ${userAgent}`)

            const now = Date.now()
            return next.handle()
                .pipe(tap(() => {
                    const response = context.switchToHttp().getResponse()
                    const { statusCode } = response
                    const contentLength = response.get("content-length")
                    const responseTime = Date.now() - now

                    this.logger.log(`'Response | ${method} ${originalUrl} ${ip} ${userAgent} ${statusCode} ${contentLength} ${responseTime}ms`)
                    this.logger.setContext("")
                }))
        } else if(context.getType() === "rpc") {
            const rpcContext = context.switchToRpc()
            const data = rpcContext.getData()
            this.logger.log(`Event Received | Payload: ${JSON.stringify(data)}`);
            return next.handle();
        }
        return next.handle()
    }
}