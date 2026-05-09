import { applyDecorators, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { SendOtpDto } from '../dto/send-otp.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';

export function SendOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Send OTP to user email' }),
    ApiBody({ type: SendOtpDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'OTP sent successfully' })
  );
}

export function VerifyOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Verify OTP' }),
    ApiBody({ type: VerifyOtpDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'Email verified successfully' }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid OTP or expired' }),
    ApiResponse({ status: HttpStatus.TOO_MANY_REQUESTS, description: 'Too many attempts' })
  );
}

export function ResendOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Resend OTP to user email' }),
    ApiBody({ type: SendOtpDto }),
    ApiResponse({ status: HttpStatus.OK, description: 'OTP sent successfully' }),
    ApiResponse({ status: HttpStatus.TOO_MANY_REQUESTS, description: 'Rate limit exceeded' })
  );
}
