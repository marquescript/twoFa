import { CallHandler, ExecutionContext, HttpException, Injectable, NestInterceptor } from "@nestjs/common";
import { Observable, catchError, throwError } from "rxjs";
import { LoggerService } from "src/config/logger/logger.service";


@Injectable()
export class LoggerErrorInterceptor implements NestInterceptor {

    constructor(
        private readonly logger: LoggerService
    ) {}

    intercept(context: ExecutionContext, next: CallHandler<any>): Observable<any> | Promise<Observable<any>> {
        const http = context.switchToHttp();
        const request = http.getRequest<Request>() as any;
        const method = request?.method;
        const path = request?.originalUrl || request?.url;

        this.logger.setContext("http.error");

        return next.handle().pipe(
            catchError((err: any) => {
                const isHttpException = err instanceof HttpException;
                const status = (isHttpException ? err.getStatus() : undefined) ?? err?.status ?? 500;
                const isUnexpected = !isHttpException || status >= 500;

                if (isUnexpected) {
                    this.logger.error("Unhandled HTTP error", {
                        method,
                        path,
                        status,
                        message: err?.message,
                        stack: err?.stack,
                    });
                }

                return throwError(() => err);
            })
        );
    }
}