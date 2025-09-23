import { INestApplication } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import * as cookieParser from "cookie-parser";
import { AuthModule } from "src/auth/auth.module";
import { LoggerService } from "src/config/logger/logger.service";
import { PrismaService } from "src/config/database/prisma.service";
import * as bcrypt from "bcryptjs"
import { AuthServiceMockTest } from "./auth-service-mock-test";
import { RedisService } from "src/config/database/redis.service";

export class AuthModuleSetup {

    public app: INestApplication
    public prisma: PrismaService
    public httpServer: any
    public authServiceMockTest: AuthServiceMockTest
    public redis: RedisService

    async setup() {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AuthModule],
            providers: [AuthServiceMockTest]
        })
        .overrideProvider(LoggerService)
        .useValue({
            setContext: () => {},
            log: () => {},
            warn: () => {},
            error: () => {},
            debug: () => {},
        })
        .compile()

        this.app = moduleFixture.createNestApplication({
            logger: false,
            bufferLogs: false
        })

        this.app.use(cookieParser())

        await this.app.init()

        this.prisma = this.app.get(PrismaService)
        this.httpServer = this.app.getHttpServer()
        this.authServiceMockTest = this.app.get(AuthServiceMockTest)
        this.redis = this.app.get(RedisService)
    }

    async teardown() {
        await this.app.close()
    }

    async cleanDatabase() {
        await this.prisma.user.deleteMany()
        await this.redis.flushall()
    }

    async seedDatabase() {
        const passwordHashed = await bcrypt.hash("password123", 8)

        const user = await this.prisma.user.create({
            data: {
                name: "John Doe",
                email: "john.doe@email.com",
                password: passwordHashed
            }
        })

        return { user }
    }

}