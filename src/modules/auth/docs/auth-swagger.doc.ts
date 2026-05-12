import { applyDecorators, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SendOtpDto } from '../dto/send-otp.dto';
import { VerifyOtpDto } from '../dto/verify-otp.dto';
import { LoginDto } from '../dto/login.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { CreateUserDTO } from '../dto/create-user.dto';

const userShape = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  full_name: 'Jane Doe',
  email: 'jane@example.com',
  avatar_url: null,
};

export function RegisterDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.CREATED),
    ApiOperation({ summary: 'Register a new user' }),
    ApiBody({ type: CreateUserDTO }),
    ApiResponse({
      status: HttpStatus.CREATED,
      description: 'User registered. OTP sent to email for verification.',
      schema: {
        example: {
          status_code: 201,
          message: 'User Created Successfully',
          data: { redirect_url: '/dashboard', user: userShape },
        },
      },
    }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Account with that email already exists.' }),
    ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: 'Database error during registration.' })
  );
}

export function SendOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Send OTP to email for verification' }),
    ApiBody({ type: SendOtpDto }),
    ApiResponse({
      status: HttpStatus.OK,
      description: 'OTP dispatched. Returns 200 even for unknown emails to prevent enumeration.',
      schema: { example: { status_code: 200, message: 'OTP sent successfully' } },
    }),
    ApiResponse({
      status: HttpStatus.TOO_MANY_REQUESTS,
      description: 'Resend cooldown active (30s). Try again shortly.',
    })
  );
}

export function VerifyOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Verify email OTP and receive auth tokens' }),
    ApiBody({ type: VerifyOtpDto }),
    ApiResponse({
      status: HttpStatus.OK,
      description:
        'Email verified. Returns JWT access token, expiry, and user. Refresh token is set as an HttpOnly cookie.',
      schema: {
        example: {
          status_code: 200,
          message: 'Email verified successfully',
          data: {
            access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
            expires_at: '2026-05-11T12:00:00.000Z',
            user: { ...userShape, is_verified: true },
          },
        },
      },
    }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid or expired OTP.' }),
    ApiResponse({ status: HttpStatus.TOO_MANY_REQUESTS, description: 'Max OTP attempts exceeded (5).' })
  );
}

export function ResendOtpDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Resend OTP to email' }),
    ApiBody({ type: SendOtpDto }),
    ApiResponse({
      status: HttpStatus.OK,
      description: 'Fresh OTP dispatched. Clears previous OTP and attempt counter.',
      schema: { example: { status_code: 200, message: 'OTP sent successfully' } },
    }),
    ApiResponse({ status: HttpStatus.TOO_MANY_REQUESTS, description: 'Resend cooldown active (30s).' })
  );
}

export function LoginDocs() {
  return applyDecorators(
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Login with email and password' }),
    ApiBody({ type: LoginDto }),
    ApiResponse({
      status: HttpStatus.OK,
      description: 'Returns JWT access token, expiry, and user. Refresh token is set as an HttpOnly cookie.',
      schema: {
        example: {
          status_code: 200,
          message: 'Login Successful',
          data: {
            access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
            expires_at: '2026-05-11T12:00:00.000Z',
            user: userShape,
          },
        },
      },
    }),
    ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid email or password.' }),
    ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Account locked. Message includes remaining seconds.' })
  );
}

export function ChangePasswordDocs() {
  return applyDecorators(
    ApiBearerAuth(),
    HttpCode(HttpStatus.OK),
    ApiOperation({ summary: 'Change authenticated user password' }),
    ApiBody({ type: ChangePasswordDto }),
    ApiResponse({
      status: HttpStatus.OK,
      description: 'Password updated.',
      schema: { example: { status_code: 200, message: 'Password updated successfully' } },
    }),
    ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Old password is incorrect.' }),
    ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Missing or invalid bearer token.' })
  );
}

export function GoogleAuthDocs() {
  return applyDecorators(
    ApiOperation({
      summary: 'Initiate Google OAuth login',
      description:
        'Cannot be tested via Swagger "Try it out". Open this URL directly in a browser tab — Passport responds with a 302 redirect to Google which AJAX cannot follow.',
    }),
    ApiResponse({ status: HttpStatus.FOUND, description: 'Redirects to Google consent screen.' })
  );
}

export function GoogleCallbackDocs() {
  return applyDecorators(
    ApiOperation({
      summary: 'Google OAuth callback (handled by Passport)',
      description:
        'Google redirects here after consent. On success, sets auth cookies and redirects to FRONTEND_URL/dashboard. On failure, redirects to FRONTEND_URL/login?error=<reason>.',
    }),
    ApiResponse({ status: HttpStatus.FOUND, description: 'Redirects to frontend dashboard on success.' }),
    ApiResponse({ status: HttpStatus.FOUND, description: 'Redirects to frontend login with error param on failure.' })
  );
}
