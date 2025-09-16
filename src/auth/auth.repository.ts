import { PrismaService } from "src/config/prisma.service";
import User from "./user.model";
import { Prisma, User as PrismaUser } from "@prisma/client";

export class AuthRepository {

    constructor(private readonly prisma: PrismaService) {}


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