import { BadRequestException, Injectable } from '@nestjs/common';
import { MailHelper } from './mail.helper';
import { UserDocument } from 'src/user/user.schema';
import { generateCode, sha256Hashing } from './code.helper';

@Injectable()
export class PasswordResetCodeHelper {
  constructor(private readonly mailHelper: MailHelper) {}
  async generateAndSendPasswordResetEmail(user: UserDocument) {
    const { passwordResetVerificationToken, code } =
      this.generateCodeVerificationDetails(user);
    const hashedCode = sha256Hashing(code);
    const hashedToken = sha256Hashing(passwordResetVerificationToken);
    await this.persistPasswordResetDetails(user, hashedCode, hashedToken);
    try {
      await this.mailHelper.sendingResetPasswordEmail(
        user.email as string,
        code,
      );
      return hashedToken;
    } catch (err) {
      await this.safeResetPasswordResetFields(user);
      throw new BadRequestException('Failed to send PasswordReset email');
    }
  }

  async generateAndResendPasswordResetCode(user: UserDocument) {
    const code = generateCode();
    const hashedCode = sha256Hashing(code);
    await this.persistPasswordResetDetails(user, hashedCode);
    try {
      await this.mailHelper.sendingResetPasswordEmail(
        user.email as string,
        code,
      );
    } catch (err) {
      await this.safeResetPasswordResetFields(user);
      throw new BadRequestException('Failed to send PasswordReset email');
    }
  }

  generateCodeVerificationDetails(user: UserDocument) {
    const code = generateCode();
    const passwordResetVerificationToken = `${user.email + code}`;
    return { passwordResetVerificationToken, code };
  }

  async persistPasswordResetDetails(
    user: UserDocument,
    hashedCode: string,
    hashedToken?: string,
  ): Promise<void> {
    user.passwordResetCode = hashedCode;
    user.passwordResetVerificationToken = hashedToken
      ? hashedToken
      : user.passwordResetVerificationToken;
    user.passwordResetCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await user.save();
  }
  async safeResetPasswordResetFields(user: UserDocument): Promise<void> {
    try {
      user.passwordResetCode = undefined;
      user.passwordResetCodeExpires = undefined;
      user.passwordResetVerificationToken = undefined;
      await user.save();
    } catch (error) {
      throw new BadRequestException('Failed to reset PasswordReset fields');
    }
  }
}
