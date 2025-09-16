import { PrismaService } from "src/config/database/prisma.service";
import User from "./user.model";
import { Prisma, User as PrismaUser } from "@prisma/client";
import { Injectable } from "@nestjs/common";

@Injectable()
export class AuthRepository {

    constructor(private readonly prisma: PrismaService) {}

    async findUserByEmail(email: string): Promise<User | null> {
        const user = await this.prisma.user.findUnique({
            where: { email }
        })

        if(!user) return null

        return this.toDomain(user)
    }

    async createUser(user: User): Promise<User> {
        const userPrisma = this.toPrisma(user)
        const createdUser = await this.prisma.user.create({
            data: userPrisma
        })

        return this.toDomain(createdUser)
    }

    async findUserById(id: string): Promise<User | null> {
        const user = await this.prisma.user.findUnique({
            where: { id }
        })

        if(!user) return null

        return this.toDomain(user)
    }

    private toPrisma(user: User): Prisma.UserCreateInput {
        return {
            email: user.email,
            name: user.name,
            password: user.password,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        }
    }

    private toDomain(user: PrismaUser): User {
        return new User({
            id: user.id,
            email: user.email,
            name: user.name,
            password: user.password,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        })
    }
}