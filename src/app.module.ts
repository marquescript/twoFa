import { Module } from '@nestjs/common';
import { EnvironmentModule } from './config/environment/environment.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    EnvironmentModule,
    AuthModule
  ],
  providers: [],
})
export class AppModule {}
