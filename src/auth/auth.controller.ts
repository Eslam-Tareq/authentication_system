import {
  Body,
  Controller,
  HttpCode,
  Post,
  HttpStatus,
  Get,
  Param,
  Put,
  Res,
  UseGuards,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';

import { SignUpDto } from './dto/sign-up.dto';
import { ResponseDto } from 'src/common/filters/response.dto';
import { ActivateEmailDto } from './dto/activate-email.dto';
import { LoginDto } from './dto/log-in.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { VerifyResetPasswordCodeDto } from './dto/verfiy-reset-password-code.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthGuard } from './auth.guard';
import { GoogleAuthService } from 'src/google/google.service';

import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('api/v1/auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly googleAuthService: GoogleAuthService,
  ) {}

  @Post('signup')
  @ApiOperation({ summary: 'Sign up new user' })
  @ApiBody({ type: SignUpDto })
  @ApiResponse({ status: 201, description: 'User signed up successfully' })
  @ApiResponse({ status: 400, description: 'Validation failed' })
  async signup(@Body() createBodyDto: SignUpDto) {
    const result = await this.authService.signup(createBodyDto);
    return ResponseDto.success({ activationToken: result });
  }

  @Post('activate-email/:activationToken')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Activate user email with code' })
  @ApiParam({ name: 'activationToken', type: String })
  @ApiBody({ type: ActivateEmailDto })
  @ApiResponse({ status: 200, description: 'Email activated successfully' })
  async activateEmail(
    @Body() activateEmailBody: ActivateEmailDto,
    @Param('activationToken') activationToken: string,
  ) {
    const result = await this.authService.activateEmail(
      activationToken,
      activateEmailBody.code,
    );
    return ResponseDto.success(result, 'email activated successfully');
  }

  @Put('resend-activation-code/:activationToken')
  @ApiOperation({ summary: 'Resend activation code to user email' })
  @ApiParam({ name: 'activationToken', type: String })
  @ApiResponse({ status: 200, description: 'Activation code resent' })
  async resendActivationCode(
    @Param('activationToken') activationToken: string,
  ) {
    const result = await this.authService.resendActivationCode(activationToken);
    return ResponseDto.success(result, 'code resent successfully');
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User login' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'User logged in or needs activation',
  })
  async login(
    @Body() loginBody: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const [isActivated, token, user] = await this.authService.logIn(loginBody);
    if (!isActivated) {
      return ResponseDto.success(
        { activationToken: token },
        'code sent to your email , please check your email inbox',
      );
    } else {
      response.cookie('accessToken', token, {
        httpOnly: true,
        sameSite: true,
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      });
      return ResponseDto.success(
        { accessToken: token, user },
        'login successfully',
      );
    }
  }

  @Post('forget-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request a password reset code' })
  @ApiBody({ type: ForgetPasswordDto })
  @ApiResponse({ status: 200, description: 'Reset code sent to email' })
  async forgotPassword(@Body() forgotPasswordDto: ForgetPasswordDto) {
    const result = await this.authService.forgetPassword(forgotPasswordDto);
    return ResponseDto.success(
      { resetVerificationToken: result },
      'code sent to your email',
    );
  }

  @Put('verify-reset-code/:resetVerificationToken')
  @ApiOperation({ summary: 'Verify reset code sent to email' })
  @ApiParam({ name: 'resetVerificationToken', type: String })
  @ApiBody({ type: VerifyResetPasswordCodeDto })
  @ApiResponse({ status: 200, description: 'Code verified successfully' })
  async verifyResetCode(
    @Param('resetVerificationToken') resetVerificationToken: string,
    @Body() verifyResetCodeDto: VerifyResetPasswordCodeDto,
  ) {
    const result = await this.authService.verifyPasswordResetCode(
      resetVerificationToken,
      verifyResetCodeDto.code,
    );
    return ResponseDto.success(
      { passwordResetToken: result },
      'code verified successfully',
    );
  }

  @Put('reset-password/:passwordResetToken')
  @ApiOperation({ summary: 'Reset user password' })
  @ApiParam({ name: 'passwordResetToken', type: String })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({ status: 200, description: 'Password reset successfully' })
  async resetPassword(
    @Param('passwordResetToken') passwordResetToken: string,
    @Body() passwordResetDto: ResetPasswordDto,
  ) {
    const result = await this.authService.resetPassword(
      passwordResetToken,
      passwordResetDto,
    );
    return ResponseDto.success(result, 'password reset successfully');
  }

  @Put('resend-reset-code/:resetVerificationToken')
  @ApiOperation({ summary: 'Resend password reset code' })
  @ApiParam({ name: 'resetVerificationToken', type: String })
  @ApiResponse({ status: 200, description: 'Code resent successfully' })
  async resendResetCode(
    @Param('resetVerificationToken') resetVerificationToken: string,
  ) {
    const result = await this.authService.resendResetCode(
      resetVerificationToken,
    );
    return ResponseDto.success(result, 'code resent successfully');
  }

  @Get('google')
  @ApiOperation({ summary: 'Initiate Google OAuth login' })
  @ApiResponse({ status: 200, description: 'Google login URL returned' })
  async googleAuth(@Res({ passthrough: true }) response: Response) {
    const authUri = this.googleAuthService.googleAuth();
    return { uri: authUri };
  }

  @Get('google/callback')
  @ApiOperation({ summary: 'Handle Google OAuth callback' })
  @ApiQuery({ name: 'code', required: true, type: String })
  @ApiResponse({ status: 200, description: 'OAuth successful' })
  async googleAuthCallback(@Query('code') code: string, @Res() res: Response) {
    return this.googleAuthService.googleAuthCallBack(code, res);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @ApiOperation({ summary: 'Logout user and clear auth cookie' })
  @ApiResponse({ status: 200, description: 'Logout successfully' })
  async logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('accessToken', { sameSite: true, httpOnly: true });
    return ResponseDto.success(undefined, 'logout successfully');
  }
}
