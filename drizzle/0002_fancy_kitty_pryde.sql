CREATE TYPE "public"."user_roles" AS ENUM('ADMIN', 'SELLER');--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "full_name" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "role" "user_roles" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "account_active" boolean DEFAULT true NOT NULL;