import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailHelper {
  constructor(private readonly mailerService: MailerService) {}
  async sendingEmail(email: string, subject: string, message: string) {
    const mailOptions: { [key: string]: any } = {
      from: `from nest auth app ${process.env.GMAIL_EMAIL}`,
      to: email,
      subject: subject,
      text: message,
    };
    await this.mailerService.sendMail(mailOptions);
  }
  async sendingActivationEmail(email: string, code: string) {
    await this.sendingEmail(
      email,
      'email activation',
      `your activation code is ${code}`,
    );
  }
  async sendingResetPasswordEmail(email: string, code: string) {
    await this.sendingEmail(
      email,
      'reset password',
      `your reset password code is valid for 10 mins ${code}`,
    );
  }
}
