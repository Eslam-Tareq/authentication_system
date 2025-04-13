import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { SignUpDto } from './dto/sign-up.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from 'src/user/user.schema';
import { Model, Types } from 'mongoose';
import { MailerService } from '@nestjs-modules/mailer';
import { LoginDto } from './dto/log-in.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    @InjectModel(User.name)
    private UserModel: Model<User>,
    private readonly mailerService: MailerService,
  ) {}
  async signup(data: SignUpDto) {
    const { name, email, password } = data;
    const hashedPassword = await this.hashingPassword(password);
    const foundUser = await this.UserModel.findOne({ email });
    if (foundUser) {
      throw new BadRequestException('user already exists');
    }
    const newUser = await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
    return await this.generateAndEmailCode(newUser);
  }
  async activateEmail(activationToken: string, code: string) {
    const hashActivationCode = this.cryptoEncryption(code);
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
    this.resettingUserCodeFields(user);
  }

  async resendActivationCode(activationToken: string) {
    const user = await this.UserModel.findOne({
      activationToken: activationToken,
    });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    const code = await this.generateAnotherActivationCode(user);
    const subject = 'email activation';
    const message = `your activation code is ${code}`;
    await this.sendingCodeToUser(user, subject, message);
  }

  async logIn(data: LoginDto) {
    const { email, password } = data;
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('email or password is incorrect');
    }
    const isPassCorrect = await this.isCorrectPassword(password, user.password);
    if (!isPassCorrect) {
      throw new BadRequestException('email or password is incorrect');
    }
    if (!user.isActivated) {
      return [false, await this.generateAndEmailCode(user)];
    } else {
      return [true, this.createAccessToken(user._id), user];
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
      await this.generateAndEmailPassResetCode(user);

    return resetVerificationToken;
  }

  async resetCodeVerified(user: UserDocument) {
    if (!user.isActivated) {
      user.isActivated = true;
      user.activationCode = undefined;
      user.activationCodeExpiresIn = undefined;
      user.activationToken = undefined;
    }
    const resetToken = `${user.email}+${user.passwordResetVerificationToken}`;
    const passwordResetToken = this.cryptoEncryption(resetToken);
    user.passwordResetToken = passwordResetToken;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpires = undefined;
    user.passwordResetVerificationToken = undefined;
    await user.save();
    return passwordResetToken;
  }
  resendResetCode = async (resetActivationToken: string) => {
    const user = await this.UserModel.findOne({
      passwordResetVerificationToken: resetActivationToken,
    });
    if (!user) {
      throw new NotFoundException('no user founded with reset token');
    }
    const code = await this.generateAnotherPassResetCode(user);
    const subject = 'password reset code';
    const message = `your password reset code is valid for (10 min) \n
      ${code}\n`;
    await this.sendingCodeToUser(user, subject, message);
  };

  async verifyPasswordResetCode(resetActivationToken: string, code: string) {
    const user = await this.UserModel.findOne({
      passwordResetVerificationToken: resetActivationToken,
    });
    if (!user) {
      throw new NotFoundException('no user founded with reset token');
    }
    const hashedCode = this.cryptoEncryption(code);
    if (
      user.passwordResetCode != hashedCode ||
      user.passwordResetCodeExpires!.getTime() < Date.now()
    ) {
      throw new BadRequestException('code is incorrect or expired');
    }
    const passwordResetToken = await this.resetCodeVerified(user);
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
    const hashedPassword = await this.hashingPassword(newPassword);
    user.password = hashedPassword;
    user.passwordChangedAt = new Date(Date.now());
    this.resettingUserCodeFields(user);
  }

  async generateAnotherActivationCode(user: UserDocument) {
    const code = this.createCode();
    const hashedCode = this.cryptoEncryption(code);

    user.activationCode = hashedCode;
    user.activationCodeExpiresIn = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await user.save();
    return code;
  }

  createAccessToken = (payload: Types.ObjectId) => {
    return this.jwtService.sign({ userId: payload });
  };
  async hashingPassword(password: string) {
    const hashedPassword = await bcrypt.hash(password, 12);
    return hashedPassword;
  }

  isCorrectPassword = async (enteredPass: string, realPass: string) => {
    return await bcrypt.compare(enteredPass, realPass);
  };
  async sendingCodeToUser(
    user: UserDocument,
    subject: string,
    message: string,
  ) {
    try {
      const mailOptions: { [key: string]: any } = {
        from: `from nest auth app ${process.env.GMAIL_EMAIL}`,
        to: user.email,
        subject: subject,
        text: message,
      };
      await this.mailerService.sendMail(mailOptions);
    } catch (err) {
      await this.resettingUserCodeFields(user);
      throw err;
    }
  }

  async resettingUserCodeFields(user: UserDocument) {
    user.activationCode = undefined;
    user.activationCodeExpiresIn = undefined;
    user.activationToken = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpires = undefined;
    user.passwordResetVerificationToken = undefined;
    user.passwordResetToken = undefined;
    user.activationCode = undefined;
    await user.save();
  }
  async generateAndEmailCode(user: UserDocument) {
    const [activationToken, code]: string[] =
      await this.generateActivationTokenAndCode(user);
    const subject = 'email activation';
    const message = `your activation code is ${code}`;
    await this.sendingCodeToUser(user, subject, message);
    return activationToken;
  }
  createCode() {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    return code;
  }
  cryptoEncryption(objective: string) {
    return crypto.createHash('sha256').update(objective).digest('hex');
  }

  async generateActivationTokenAndCode(user: UserDocument) {
    const code = this.createCode();
    const hashedCode = this.cryptoEncryption(code);
    const activationToken = `${user.email + code}`;
    const hashedActivationToken = this.cryptoEncryption(activationToken);
    user.activationCode = hashedCode;
    user.activationCodeExpiresIn = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    user.activationToken = hashedActivationToken;
    await user.save();
    return [hashedActivationToken, code];
  }
  async generatePassResetTokenAndCode(user: UserDocument) {
    const code = this.createCode();
    const hashedCode = this.cryptoEncryption(code);

    const activationToken = `${user.email + code}`;
    const hashedActivationToken = this.cryptoEncryption(activationToken);

    user.passwordResetCode = hashedCode;
    user.passwordResetCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    user.passwordResetVerificationToken = hashedActivationToken;
    await user.save();
    return [hashedActivationToken, code];
  }

  async generateAndEmailPassResetCode(user: UserDocument) {
    const [hashedActivationToken, code]: string[] =
      await this.generatePassResetTokenAndCode(user);

    const subject = 'password reset code';
    const message = `your password reset code is valid for (10 min) \n
    ${code}\n`;
    await this.sendingCodeToUser(user, subject, message);
    return hashedActivationToken;
  }

  async generateAnotherPassResetCode(user: UserDocument) {
    const code = this.createCode();
    const hashedCode = this.cryptoEncryption(code);

    user.passwordResetCode = hashedCode;
    user.passwordResetCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await user.save();
    return code;
  }
}
