import {
  Body,
  Controller,
  HttpCode,
  HttpException,
  Post,
  Req,
  HttpStatus,
  UseFilters,
  Get,
  Param,
  Put,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request, Response } from 'express';
import { CustomExceptionFilter } from 'src/common/filters/http-exception.filter';
import { CatchEverythingFilter } from 'src/common/filters/custom-exception.filter';
import { SignUpDto } from './dto/sign-up.dto';
import { ResponseDto } from 'src/common/filters/response.dto';
import { ActivateEmailDto } from './dto/activate-email.dto';
import { LoginDto } from './dto/log-in.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { VerifyResetPasswordCodeDto } from './dto/verfiy-reset-password-code.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthGuard } from './auth.guard';
@Controller('auth')
//@UseFilters( CatchEverythingFilter)
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Post('signup')
  async signup(@Body() createBodyDto: SignUpDto) {
    try {
      const result = await this.authService.signup(createBodyDto);
      return ResponseDto.success({ activationToken: result });
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Post('activate-email/:activationToken')
  @HttpCode(HttpStatus.OK)
  async activateEmail(
    @Body() activateEmailBody: ActivateEmailDto,
    @Param('activationToken') activationToken: string,
  ) {
    try {
      const result = await this.authService.activateEmail(
        activationToken,
        activateEmailBody.code,
      );
      return ResponseDto.success(result, 'email activated successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Put('resend-activation-code/:activationToken')
  async resendActivationCode(
    @Param('activationToken') activationToken: string,
  ) {
    try {
      const result =
        await this.authService.resendActivationCode(activationToken);
      return ResponseDto.success(result, 'code resent successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginBody: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const [isActivated, token, user] =
        await this.authService.logIn(loginBody);
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
      //return ResponseDto.success(result, 'login successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Post('forget-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgetPasswordDto) {
    try {
      const result = await this.authService.forgetPassword(forgotPasswordDto);
      return ResponseDto.success(
        { resetVerificationToken: result },
        'code sent to your email',
      );
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Put('verify-reset-code/:resetVerificationToken')
  async verifyResetCode(
    @Param('resetVerificationToken') resetVerificationToken: string,
    @Body() verifyResetCodeDto: VerifyResetPasswordCodeDto,
  ) {
    try {
      const result = await this.authService.verifyPasswordResetCode(
        resetVerificationToken,
        verifyResetCodeDto.code,
      );
      return ResponseDto.success(
        { passwordResetToken: result },
        'code verified successfully',
      );
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Put('reset-password/:passwordResetToken')
  async resetPassword(
    @Param('passwordResetToken') passwordResetToken: string,
    @Body() passwordResetDto: ResetPasswordDto,
  ) {
    try {
      const result = await this.authService.resetPassword(
        passwordResetToken,
        passwordResetDto,
      );
      return ResponseDto.success(result, 'password reset successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Put('resend-reset-code/:resetVerificationToken')
  async resendResetCode(
    @Param('resetVerificationToken') resetVerificationToken: string,
  ) {
    try {
      const result = await this.authService.resendResetCode(
        resetVerificationToken,
      );
      return ResponseDto.success(result, 'code resent successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  async logout(@Res({ passthrough: true }) res: Response) {
    try {
      res.clearCookie('accessToken', { sameSite: true, httpOnly: true });
      return ResponseDto.success(undefined, 'logout successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
}
