/*
  Warnings:

  - Changed the type of `twoFaEnabled` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- CreateEnum
CREATE TYPE "public"."EnableTwoFaStatus" AS ENUM ('ENABLED', 'PENDING');

-- AlterTable
ALTER TABLE "public"."User" DROP COLUMN "twoFaEnabled",
ADD COLUMN     "twoFaEnabled" "public"."EnableTwoFaStatus" NOT NULL;
