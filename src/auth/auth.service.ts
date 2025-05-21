import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/sign-up.dto';

import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/user/user.schema';
import { Model, Types } from 'mongoose';
import { LoginDto } from './dto/log-in.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ActivationCodeHelper } from './helpers/activation-code.helper';
import { resettingUserCodeFields, sha256Hashing } from './helpers/code.helper';
import { PasswordResetCodeHelper } from './helpers/password-code.helper';
import { hashingPassword, isCorrectPassword } from './helpers/password.helper';
import { TokenService } from 'src/jwt/jwt.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: TokenService,
    @InjectModel(User.name)
    private UserModel: Model<User>,
    private readonly activationCodeHelper: ActivationCodeHelper,
    private readonly passwordResetCodeHelper: PasswordResetCodeHelper,
  ) {}
  async signup(data: SignUpDto) {
    const { name, email, password } = data;
    const hashedPassword = await hashingPassword(password);
    const foundUser = await this.UserModel.findOne({ email });
    if (foundUser) {
      throw new BadRequestException('user already exists');
    }
    const newUser = await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
    return await this.activationCodeHelper.generateAndSendActivation(newUser);
  }
  async activateEmail(activationToken: string, code: string) {
    const hashActivationCode = sha256Hashing(code);
    const user = await this.UserModel.findOne({
      activationToken: activationToken,
    });
    if (!user) {
      throw new NotFoundException('user not found');
    }

    if (
      user.activationCode != hashActivationCode ||
      user.activationCodeExpiresIn!.getTime() < Date.now()
    ) {
      throw new BadRequestException('code is incorrect or expired');
    }
    user.isActivated = true;
    await this.activationCodeHelper.safeResetActivationFields(user);
  }

  async resendActivationCode(activationToken: string) {
    const user = await this.UserModel.findOne({
      activationToken: activationToken,
    });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    await this.activationCodeHelper.generateAndResendActivationCode(user);
  }

  async logIn(data: LoginDto) {
    const { email, password } = data;
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('email or password is incorrect');
    }
    const isPassCorrect = await isCorrectPassword(password, user.password);
    if (!isPassCorrect) {
      throw new BadRequestException('email or password is incorrect');
    }
    if (!user.isActivated) {
      return [
        false,
        await this.activationCodeHelper.generateAndSendActivation(user),
      ];
    } else {
      const accessToken = this.jwtService.generateAccessToken(user);
      return [true, accessToken, user];
    }
  }

  async forgetPassword(forgetPasswordDto: ForgetPasswordDto) {
    const user = await this.UserModel.findOne({
      email: forgetPasswordDto.email,
    });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    const resetVerificationToken =
      await this.passwordResetCodeHelper.generateAndSendPasswordResetEmail(
        user,
      );

    return resetVerificationToken;
  }

  resendResetCode = async (resetActivationToken: string) => {
    const user = await this.UserModel.findOne({
      passwordResetVerificationToken: resetActivationToken,
    });
    if (!user) {
      throw new NotFoundException('no user founded with reset token');
    }
    await this.passwordResetCodeHelper.generateAndResendPasswordResetCode(user);
  };

  async verifyPasswordResetCode(resetActivationToken: string, code: string) {
    const user = await this.UserModel.findOne({
      passwordResetVerificationToken: resetActivationToken,
    });
    if (!user) {
      throw new NotFoundException('no user founded with reset token');
    }
    const hashedCode = sha256Hashing(code);
    if (
      user.passwordResetCode != hashedCode ||
      user.passwordResetCodeExpires!.getTime() < Date.now()
    ) {
      throw new BadRequestException('code is incorrect or expired');
    }
    if (!user.isActivated) {
      user.isActivated = true;
      user.activationCode = undefined;
      user.activationCodeExpiresIn = undefined;
      user.activationToken = undefined;
    }
    const resetToken = `${user.email}+${user.passwordResetVerificationToken}`;
    const passwordResetToken = sha256Hashing(resetToken);
    user.passwordResetToken = passwordResetToken;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpires = undefined;
    user.passwordResetVerificationToken = undefined;
    await user.save();
    return passwordResetToken;
  }

  async resetPassword(
    passwordResetToken: string,
    passwordResetDto: ResetPasswordDto,
  ) {
    const { newPassword } = passwordResetDto;
    const user = await this.UserModel.findOne({
      passwordResetToken,
    });
    if (!user) {
      throw new NotFoundException('no user founded with reset token');
    }
    const hashedPassword = await hashingPassword(newPassword);
    user.password = hashedPassword;
    user.passwordChangedAt = new Date(Date.now());
    await resettingUserCodeFields(user);
  }
}
