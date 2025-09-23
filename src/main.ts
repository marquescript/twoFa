import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from "cookie-parser";
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { EnvironmentService } from './config/environment/environment.service';
import { LoggerService } from './config/logger/logger.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  const environmentService = app.get(EnvironmentService)
  const logger = await app.resolve(LoggerService)

  app.useLogger(logger)
  
  app.use(cookieParser())

  app.enableCors({
    origin: ["*"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })

  const config = new DocumentBuilder()
    .setTitle("Two Factor Authentication API")
    .setDescription("API for two factor authentication")
    .setVersion("1.0")
    .addBearerAuth()
    .addCookieAuth("refresh_token", { 
      type: "apiKey", 
      in: "cookie", 
      name: "refresh_token", 
      description: "Refresh token HTTP-only cookie"
    })
    .build()

  const documentFactory = () => SwaggerModule.createDocument(app, config)
  SwaggerModule.setup("api", app, documentFactory)

  logger.log(`Swagger documentation is available at http://localhost:${environmentService.get("PORT")}/api`)
  logger.log(`Server is running on port ${environmentService.get("PORT")}`)
  await app.listen(environmentService.get("PORT"));
}
bootstrap();
