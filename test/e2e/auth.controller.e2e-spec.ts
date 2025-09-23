import { CreateUserDto } from "src/auth/dto/create-user.dto"
import { AuthModuleSetup } from "./auth-module-setup"
import * as request from 'supertest';
import { HttpStatus } from "@nestjs/common";
import { LoginDto } from "src/auth/dto/login.dto";
import * as otplib from "otplib";
import { encrypt } from "src/auth/utils/crypto";
import { EnvironmentService } from "src/config/environment/environment.service";

describe("AuthController (e2e)", () => {

    const setupContext = new AuthModuleSetup()
    let seededDatabase: Awaited<ReturnType<typeof setupContext.seedDatabase>>

    beforeAll(async () => await setupContext.setup())

    beforeEach(async () => {
        await setupContext.cleanDatabase()
        seededDatabase = await setupContext.seedDatabase()
    })

    afterAll(async () => await setupContext.teardown())

    describe("e2e /auth", () => {

        describe("POST /register", () => {

            it("shold create a new user", async () => {
                const createUserDto: CreateUserDto = {
                    email: "test@test.com",
                    name: "Test",
                    password: "password123"
                }
    
                const response = await request(setupContext.httpServer)
                    .post("/auth/register")
                    .send(createUserDto)
                    .expect(HttpStatus.CREATED)
                    .expect('set-cookie', /refresh_token=.*/)
    
                const body = response.body
    
                expect(body.accessToken).toBeDefined()
                
                const cookies = Array.isArray(response.headers['set-cookie']) 
                    ? response.headers['set-cookie'] 
                    : [response.headers['set-cookie']]
                expect(cookies).toBeDefined()
                expect(cookies.some((cookie: string) => cookie.startsWith('refresh_token='))).toBe(true)
    
                const userInDb = await setupContext.prisma.user.findUnique({
                    where: { email: createUserDto.email }
                })
    
                expect(userInDb).toBeDefined()
                expect(userInDb?.email).toEqual(createUserDto.email)
            })

            it("should return a conflict error if the email already exists", async () => {

                const createUserDto: CreateUserDto = {
                    email: seededDatabase.user.email,
                    name: "Test",
                    password: "password123"
                }

                await request(setupContext.httpServer)
                    .post("/auth/register")
                    .send(createUserDto)
                    .expect(HttpStatus.CONFLICT)
            })
        })

        describe("POST /login", () => {

            it("should login a user", async () => {

                const loginDto: LoginDto = {
                    email: seededDatabase.user.email,
                    password: "password123"
                }

                const response = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.OK)
                    .expect('set-cookie', /refresh_token=.*/)

                const body = response.body

                expect(body.accessToken).toBeDefined()
                
                const cookies = Array.isArray(response.headers['set-cookie']) 
                    ? response.headers['set-cookie'] 
                    : [response.headers['set-cookie']]
                expect(cookies).toBeDefined()
                expect(cookies.some((cookie: string) => cookie.startsWith('refresh_token='))).toBe(true)

            })

            it("should return a two factor authentication required error if the user has two factor authentication enabled", async () => {
                
                const loginDto: LoginDto = {
                    email: seededDatabase.user.email,
                    password: "password123"
                }

                await setupContext.prisma.user.update({
                    data: {
                        twoFaEnabled: true
                    },
                    where: {
                        id: seededDatabase.user.id
                    }
                })

                const response = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.UNAUTHORIZED)

                const body = response.body
                expect(body["errorCode"]).toBe("2FA_REQUIRED")
            })

            it("should return a invalid credentials error if the two factor authentication token is invalid", async () => {
                
                const twoFaSecret = otplib.authenticator.generateSecret()

                const encryptedTwoFaSecret = encrypt(twoFaSecret, setupContext.app.get(EnvironmentService).get("ENCRYPTION_KEY"))

                await setupContext.prisma.user.update({
                    where: {
                        id: seededDatabase.user.id
                    },
                    data: { twoFaEnabled: true, twoFaSecret: encryptedTwoFaSecret }
                })

                const loginDto: LoginDto = {
                    email: seededDatabase.user.email,
                    password: "password123",
                    twoFaToken: "123456",
                }

                await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.UNAUTHORIZED)
            })

            it("should return a invalid backup code error if the backup code is invalid", async () => {

                const { hashedBackupCodes } = await setupContext.authServiceMockTest.generateBackupCodesTest()

                const twoFaSecret = otplib.authenticator.generateSecret()

                const encryptedTwoFaSecret = encrypt(twoFaSecret, setupContext.app.get(EnvironmentService).get("ENCRYPTION_KEY"))

                const user = await setupContext.prisma.user.update({
                    where: { id: seededDatabase.user.id },
                    data: { backupCodes: hashedBackupCodes, twoFaEnabled: true, twoFaSecret: encryptedTwoFaSecret }
                })

                const loginDto: LoginDto = {
                    email: user.email,
                    password: "password123",
                    backupCode: "invalid_backup_code"
                }

                const response = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.UNAUTHORIZED)

                const body = response.body

                expect(body.message).toBe("Invalid backup code")
            })

            it("should return success if the backup code is valid", async () => {
                const { backupCodes, hashedBackupCodes } = await setupContext.authServiceMockTest.generateBackupCodesTest()

                const twoFaSecret = otplib.authenticator.generateSecret()

                const encryptedTwoFaSecret = encrypt(twoFaSecret, setupContext.app.get(EnvironmentService).get("ENCRYPTION_KEY"))

                const user = await setupContext.prisma.user.update({
                    where: { id: seededDatabase.user.id },
                    data: { backupCodes: hashedBackupCodes, twoFaEnabled: true, twoFaSecret: encryptedTwoFaSecret }
                })

                const loginDto: LoginDto = {
                    email: user.email,
                    password: "password123",
                    backupCode: backupCodes[0]
                }

                const response = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.OK)

                expect(response.body.accessToken).toBeDefined()

                const isRemovedFromBackupCodesInDb = await setupContext.prisma.user.findUnique({
                    where: { id: user.id }
                })

                expect(isRemovedFromBackupCodesInDb?.backupCodes).not.toContain(hashedBackupCodes[0])
                expect(isRemovedFromBackupCodesInDb?.backupCodes).toHaveLength(hashedBackupCodes.length - 1)
            })
        })

        describe("POST /enable-two-fa", () => {

            it("should confirm two factor authentication", async () => {
    
                const accessToken = await setupContext.authServiceMockTest.generateAccessTokenTest(
                    seededDatabase.user.id,
                    seededDatabase.user.email,
                    setupContext.app.get(EnvironmentService).get("JWT_PRIVATE_KEY")
                )

                await request(setupContext.httpServer)
                    .post("/auth/enable-two-fa")
                    .set("Authorization", `Bearer ${accessToken}`)
                    .expect(HttpStatus.OK)

                const isTwoFaEnabledInDb = await setupContext.prisma.user.findUnique({
                    where: { id: seededDatabase.user.id }
                })

                expect(isTwoFaEnabledInDb?.twoFaSecret).toBeDefined()
            })
        })

        describe("POST /confirm-two-fa", () => {

            it("should confirm two factor authentication", async () => {

                const twoFaSecret = otplib.authenticator.generateSecret()
                const encryptedTwoFaSecret = encrypt(twoFaSecret, setupContext.app.get(EnvironmentService).get("ENCRYPTION_KEY"))

                await setupContext.prisma.user.update({
                    where: { id: seededDatabase.user.id },
                    data: { twoFaSecret: encryptedTwoFaSecret }
                })

                const accessToken = await setupContext.authServiceMockTest.generateAccessTokenTest(
                    seededDatabase.user.id,
                    seededDatabase.user.email,
                    setupContext.app.get(EnvironmentService).get("JWT_PRIVATE_KEY")
                )

                const validTwoFaCode = setupContext.authServiceMockTest.generateValidTwoFaToken(twoFaSecret)

                const response = await request(setupContext.httpServer)
                    .post("/auth/confirm-two-fa")
                    .set("Authorization", `Bearer ${accessToken}`)
                    .send({ token: validTwoFaCode })
                    .expect(HttpStatus.OK)

                expect(response.body.backupCodes).toBeDefined()
                expect(response.body.backupCodes).toHaveLength(8)

                const userInDb = await setupContext.prisma.user.findUnique({
                    where: { id: seededDatabase.user.id }
                })

                expect(userInDb?.twoFaEnabled).toBe(true)
                expect(userInDb?.backupCodes).toHaveLength(8)
            })
        })

        describe("POST /disable-two-fa", () => {

            it("should disable two factor authentication", async () => {
                
                const accessToken = await setupContext.authServiceMockTest.generateAccessTokenTest(
                    seededDatabase.user.id,
                    seededDatabase.user.email,
                    setupContext.app.get(EnvironmentService).get("JWT_PRIVATE_KEY")
                )

                const twoFaSecret = otplib.authenticator.generateSecret()

                const encryptedTwoFaSecret = encrypt(twoFaSecret, setupContext.app.get(EnvironmentService).get("ENCRYPTION_KEY"))

                const { hashedBackupCodes } = await setupContext.authServiceMockTest.generateBackupCodesTest()

                await setupContext.prisma.user.update({
                    where: { id: seededDatabase.user.id },
                    data: { twoFaEnabled: true, twoFaSecret: encryptedTwoFaSecret, backupCodes: hashedBackupCodes }
                })

                await request(setupContext.httpServer)
                    .post("/auth/disable-two-fa")
                    .set("Authorization", `Bearer ${accessToken}`)
                    .expect(HttpStatus.OK)

                const userInDb = await setupContext.prisma.user.findUnique({
                    where: { id: seededDatabase.user.id }
                })

                expect(userInDb?.twoFaEnabled).toBe(false)
                expect(userInDb?.twoFaSecret).toBeNull()
                expect(userInDb?.backupCodes).toHaveLength(0)
            })
        })

        describe("POST /refresh", () => {

            it("should refresh token if the refresh token is valid", async () => {

                const responseLogin = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send({
                        email: seededDatabase.user.email,
                        password: "password123"
                    })

                const refreshToken = setupContext.authServiceMockTest.getRefreshTokenFromHeaders(responseLogin)

                const response = await request(setupContext.httpServer)
                    .post("/auth/refresh")
                    .set("Cookie", `refresh_token=${refreshToken}`)
                    .expect(HttpStatus.OK)

                const rawSetCookie = response.headers['set-cookie']
                expect(rawSetCookie).toBeDefined()
                const setCookies = Array.isArray(rawSetCookie) ? rawSetCookie : [rawSetCookie as string]

                const refreshCookie = setCookies.find((c: string) => c.startsWith('refresh_token='))
                expect(refreshCookie).toBeDefined()

                const [, cookieValue] = (refreshCookie as string).split('refresh_token=')

                expect(response.body.accessToken).toBeDefined()
                expect(setCookies).toBeDefined()
                expect(Array.isArray(setCookies)).toBe(true)
                expect(cookieValue).toBeTruthy()
            })

            it("should return a unauthorized error if the refresh token is invalid", async () => {
                
                const loginDto: LoginDto = {
                    email: seededDatabase.user.email,
                    password: "password123"
                }

                const responseFirstLogin = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.OK)

                const refreshTokenFirstLogin = setupContext.authServiceMockTest.getRefreshTokenFromHeaders(responseFirstLogin)

                await request(setupContext.httpServer)
                    .post("/auth/refresh")
                    .set("Cookie", `refresh_token=${refreshTokenFirstLogin}`)
                    .expect(HttpStatus.OK)

                await request(setupContext.httpServer)
                    .post("/auth/refresh")
                    .set("Cookie", `refresh_token=${refreshTokenFirstLogin}`)
                    .expect(HttpStatus.UNAUTHORIZED)
            })
        })

        describe("POST /logout", () => {

            it("should logout a user", async () => {

                const loginDto: LoginDto = {
                    email: seededDatabase.user.email,
                    password: "password123"
                }

                const responseLogin = await request(setupContext.httpServer)
                    .post("/auth/login")
                    .send(loginDto)
                    .expect(HttpStatus.OK)

                const accessToken = responseLogin.body.accessToken

                await request(setupContext.httpServer)
                    .post("/auth/logout")
                    .set("Authorization", `Bearer ${accessToken}`)
                    .expect(HttpStatus.OK)

                await request(setupContext.httpServer)
                    .post("/auth/enable-two-fa")
                    .set("Authorization", `Bearer ${accessToken}`)
                    .expect(HttpStatus.UNAUTHORIZED)
            })
        })
    })

})