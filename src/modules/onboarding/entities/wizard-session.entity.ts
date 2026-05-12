import { Column, Entity, Index, ManyToOne, JoinColumn, CreateDateColumn } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { AbstractBaseEntity } from '../../../entities/base.entity';
import { User } from '@modules/user/entities/user.entity';

export enum WizardSessionStatus {
    IN_PROGRESS = 'in_progress',
    COMPLETE = 'complete',
    EXPIRED = 'expired',
}

@Entity({ name: 'wizard_sessions' })
@Index('IDX_wizard_sessions_user_status_created', ['user_id', 'status', 'created_at'])
@Index('IDX_wizard_sessions_user_in_progress', ['user_id'], {
    where: `"status" = '${WizardSessionStatus.IN_PROGRESS}'`,
    unique: true,
})
export class WizardSession extends AbstractBaseEntity {
    @ApiProperty({ type: String, description: 'Foreign key to users table' })
    @Column({ type: 'uuid', nullable: false })
    user_id: string;

    @ApiProperty({ enum: WizardSessionStatus, description: 'Status of the wizard session' })
    @Column({
        type: 'enum',
        enum: WizardSessionStatus,
        default: WizardSessionStatus.IN_PROGRESS,
    })
    status: WizardSessionStatus;

    @ApiProperty({ type: Number, description: 'Number of steps completed' })
    @Column({ type: 'integer', default: 0 })
    steps_completed: number;

    @ApiProperty({ type: Object, description: 'Polymorphic step data stored as JSONB' })
    @Column({ type: 'jsonb', nullable: false, default: {} })
    answers: Record<string, any>;

    @ApiProperty({ description: 'Timestamp when the session was created' })
    @CreateDateColumn({ name: 'created_at', type: 'timestamp with time zone' })
    created_at: Date;

    @ApiProperty({ description: 'Timestamp when the session will expire (NOW() + 24 hours)' })
    @Column({ type: 'timestamp with time zone', nullable: false })
    expires_at: Date;

    @ManyToOne(() => User, (user) => user.wizard_sessions, {
        onDelete: 'CASCADE',
        nullable: false,
    })
    @JoinColumn({ name: 'user_id' })
    user: User;
}
