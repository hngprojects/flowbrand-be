import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as SYS_MSG from '@shared/constants/SystemMessages';
import { CustomHttpException } from '@shared/helpers/custom-http-filter';
import { User } from '@modules/user/entities/user.entity';
import { CreateUserDTO } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { RedisService } from '@modules/redis/services/redis.service';
import { EmailService } from '@modules/email/email.service';

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 10;

@Injectable()
export default class AuthenticationService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly emailService: EmailService
  ) {}

  async createNewUser(createUserDto: CreateUserDTO) {
    const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
    if (existing) {
      throw new CustomHttpException(SYS_MSG.USER_ACCOUNT_EXIST, HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = this.userRepository.create({
      email: createUserDto.email,
      full_name: createUserDto.full_name,
      country: createUserDto.country ?? null,
      password: hashedPassword,
      auth_provider: 'email',
      otp_code: this.generateOtp(),
      expires_at: this.computeOtpExpiry(),
    });
    const saved = await this.userRepository.save(user);

    const hashedOtp = await bcrypt.hash(user.otp_code, 10);
    await this.redisService.set(`otp:${saved.email}`, hashedOtp, OTP_EXPIRY_MINUTES * 60);
    await this.emailService.sendUserEmailConfirmationOtp(saved.email, user.otp_code);

    const access_token = this.jwtService.sign({ id: saved.id, sub: saved.id, email: saved.email });

    return {
      status_code: HttpStatus.CREATED,
      message: SYS_MSG.USER_CREATED_SUCCESSFULLY,
      access_token,
      data: {
        user: {
          id: saved.id,
          full_name: saved.full_name,
          email: saved.email,
          avatar_url: saved.avatar_url,
        },
      },
    };
  }

  async loginUser(loginDto: LoginDto) {
    const user = await this.userRepository.findOne({ where: { email: loginDto.email } });
    if (!user || !user.password) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const isMatch = await bcrypt.compare(loginDto.password, user.password);
    if (!isMatch) {
      throw new CustomHttpException(SYS_MSG.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    const access_token = this.jwtService.sign({ id: user.id, sub: user.id, email: user.email });

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.LOGIN_SUCCESSFUL,
      access_token,
      data: {
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          avatar_url: user.avatar_url,
        },
      },
    };
  }

  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    if (!user.password || !(await bcrypt.compare(oldPassword, user.password))) {
      throw new CustomHttpException(SYS_MSG.INVALID_PASSWORD, HttpStatus.BAD_REQUEST);
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await this.userRepository.save(user);

    return {
      status_code: HttpStatus.OK,
      message: SYS_MSG.PASSWORD_UPDATED,
    };
  }

  async sendOtp(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    const otp = this.generateOtp();
    user.otp_code = otp;
    user.expires_at = this.computeOtpExpiry();
    await this.userRepository.save(user);

    const hashedOtp = await bcrypt.hash(otp, 10);
    await this.redisService.set(`otp:${email}`, hashedOtp, OTP_EXPIRY_MINUTES * 60);
    await this.redisService.set(`limit:${email}`, '1', 30);
    
    await this.emailService.sendUserEmailConfirmationOtp(email, otp);

    return {
      status_code: HttpStatus.OK,
      message: 'OTP sent successfully',
    };
  }

  async verifyOtp(email: string, otp: string) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new CustomHttpException(SYS_MSG.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    const attemptsKey = `attempts:${email}`;
    const attempts = await this.redisService.incr(attemptsKey);
    if (attempts === 1) {
      await this.redisService.set(attemptsKey, '1', OTP_EXPIRY_MINUTES * 60);
    }
    
    if (attempts && attempts > 5) {
      throw new CustomHttpException('Too many attempts. Please request a new OTP.', HttpStatus.TOO_MANY_REQUESTS);
    }

    const hashedOtp = await this.redisService.get(`otp:${email}`);
    if (!hashedOtp) {
      throw new CustomHttpException('OTP has expired or does not exist', HttpStatus.BAD_REQUEST);
    }

    const isMatch = await bcrypt.compare(otp, hashedOtp);
    if (!isMatch) {
      throw new CustomHttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
    }

    user.is_verified = true;
    await this.userRepository.save(user);

    await this.redisService.del(`otp:${email}`);
    await this.redisService.del(`attempts:${email}`);
    await this.redisService.del(`limit:${email}`);

    const access_token = this.jwtService.sign({ id: user.id, sub: user.id, email: user.email });

    return {
      status_code: HttpStatus.OK,
      message: 'Email verified successfully',
      access_token,
      data: {
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          avatar_url: user.avatar_url,
          is_verified: user.is_verified,
        },
      },
    };
  }

  async resendOtp(email: string) {
    const hasLimit = await this.redisService.exists(`limit:${email}`);
    if (hasLimit) {
      throw new CustomHttpException('Please wait before requesting another OTP', HttpStatus.TOO_MANY_REQUESTS);
    }

    return this.sendOtp(email);
  }

  private generateOtp(): string {
    return Math.floor(Math.random() * 10 ** OTP_LENGTH)
      .toString()
      .padStart(OTP_LENGTH, '0');
  }

  private computeOtpExpiry(): Date {
    return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
  }
}
