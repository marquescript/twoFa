-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "twoFaEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "twoFaSecret" TEXT;
