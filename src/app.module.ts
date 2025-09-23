import { Module } from '@nestjs/common';
import { EnvironmentModule } from './config/environment/environment.module';
import { AuthModule } from './auth/auth.module';
import { InterceptorModule } from './interceptors/interceptor.module';
import { LoggerModule } from './config/logger/logger.module';

@Module({
  imports: [
    EnvironmentModule,
    AuthModule,
    InterceptorModule,
    LoggerModule
  ],
  providers: [],
})
export class AppModule {}
