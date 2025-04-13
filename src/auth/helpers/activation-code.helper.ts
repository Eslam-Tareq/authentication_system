import { BadRequestException, Injectable } from '@nestjs/common';
import { MailHelper } from './mail.helper';
import { UserDocument } from 'src/user/user.schema';
import { generateCode, sha256Hashing } from './code.helper';

@Injectable()
export class ActivationCodeHelper {
  constructor(private readonly mailHelper: MailHelper) {}
  // this for generate activation code and send it to the user email
  async generateAndSendActivation(user: UserDocument) {
    const { activationToken, code } = this.generateActivationDetails(user);
    const hashedCode = sha256Hashing(code);
    const hashedToken = sha256Hashing(activationToken);
    //saving the activation code and token in the user document
    await this.persistActivationDetails(user, hashedCode, hashedToken);
    try {
      await this.mailHelper.sendingActivationEmail(user.email as string, code);
      return hashedToken;
    } catch (err) {
      // if the email sending fails, reset the activation fields in the user document
      await this.safeResetActivationFields(user);
      throw new BadRequestException('Failed to send activation email');
    }
  }
  // this for generate new activation code and send it to the user email

  async generateAndResendActivationCode(user: UserDocument) {
    const code = generateCode();
    const hashedCode = sha256Hashing(code);
    await this.persistActivationDetails(user, hashedCode);
    try {
      await this.mailHelper.sendingActivationEmail(user.email as string, code);
    } catch (err) {
      await this.safeResetActivationFields(user);
      throw new BadRequestException('Failed to send activation email');
    }
  }

  // this for generate activation code and token
  generateActivationDetails(user: UserDocument) {
    const code = generateCode();
    const activationToken = `${user.email + code}`;
    return { activationToken, code };
  }

  // this for saving the activation code and token in the user document
  async persistActivationDetails(
    user: UserDocument,
    hashedCode: string,
    hashedToken?: string,
  ): Promise<void> {
    user.activationCode = hashedCode;
    user.activationToken = hashedToken ? hashedToken : user.activationToken;
    user.activationCodeExpiresIn = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await user.save();
  }
  // this for resetting the activation fields in the user document
  async safeResetActivationFields(user: UserDocument): Promise<void> {
    try {
      user.activationCode = undefined;
      user.activationCodeExpiresIn = undefined;
      user.activationToken = undefined;
      await user.save();
    } catch (error) {
      throw new BadRequestException('Failed to reset activation fields');
    }
  }
}
