-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "backup_codes" TEXT[] DEFAULT ARRAY[]::TEXT[];
