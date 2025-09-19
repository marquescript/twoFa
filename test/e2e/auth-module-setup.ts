import { INestApplication } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import * as cookieParser from "cookie-parser";
import { AuthModule } from "src/auth/auth.module";
import { PrismaService } from "src/config/database/prisma.service";
import * as bcrypt from "bcryptjs"
import { AuthServiceMockTest } from "./auth-service-mock-test";

export class AuthModuleSetup {

    public app: INestApplication
    public prisma: PrismaService
    public httpServer: any
    public authServiceMockTest: AuthServiceMockTest

    async setup() {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AuthModule],
            providers: [AuthServiceMockTest]
        }).compile()

        this.app = moduleFixture.createNestApplication()

        this.app.use(cookieParser())

        await this.app.init()

        this.prisma = this.app.get(PrismaService)
        this.httpServer = this.app.getHttpServer()
        this.authServiceMockTest = this.app.get(AuthServiceMockTest)
    }

    async teardown() {
        await this.app.close()
    }

    async cleanDatabase() {
        await this.prisma.user.deleteMany()
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