/*
  Warnings:

  - You are about to drop the column `twoFaEnabled` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `twoFaSecret` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "public"."User" DROP COLUMN "twoFaEnabled",
DROP COLUMN "twoFaSecret",
ADD COLUMN     "two_fa_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "two_fa_secret" TEXT;
