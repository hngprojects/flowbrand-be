import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateWizardSessions1778586510 implements MigrationInterface {
    name = 'CreateWizardSessions1778586510';

    public async up(queryRunner: QueryRunner): Promise<void> {
        // Create ENUM type for wizard session status
        await queryRunner.query(
            `CREATE TYPE "public"."wizard_sessions_status_enum" AS ENUM('in_progress', 'complete', 'expired')`,
        );

        // Create wizard_sessions table
        await queryRunner.query(
            `CREATE TABLE "wizard_sessions" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "user_id" uuid NOT NULL,
        "status" "public"."wizard_sessions_status_enum" NOT NULL DEFAULT 'in_progress',
        "steps_completed" integer NOT NULL DEFAULT '0',
        "answers" jsonb NOT NULL DEFAULT '{}',
        "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
        CONSTRAINT "PK_wizard_sessions_id" PRIMARY KEY ("id"),
        CONSTRAINT "FK_wizard_sessions_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
      )`,
        );

        // Create composite index on (user_id, status, created_at)
        await queryRunner.query(
            `CREATE INDEX "IDX_wizard_sessions_user_status_created" ON "wizard_sessions" ("user_id", "status", "created_at")`,
        );

        // Create unique partial index on user_id where status = 'in_progress'
        // This ensures only one active session per user
        await queryRunner.query(
            `CREATE UNIQUE INDEX "IDX_wizard_sessions_user_in_progress" ON "wizard_sessions" ("user_id") WHERE "status" = 'in_progress'`,
        );
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        // Drop indexes
        await queryRunner.query(`DROP INDEX IF EXISTS "IDX_wizard_sessions_user_in_progress"`);
        await queryRunner.query(`DROP INDEX IF EXISTS "IDX_wizard_sessions_user_status_created"`);

        // Drop table
        await queryRunner.query(`DROP TABLE IF EXISTS "wizard_sessions"`);

        // Drop ENUM type
        await queryRunner.query(`DROP TYPE IF EXISTS "public"."wizard_sessions_status_enum"`);
    }
}
