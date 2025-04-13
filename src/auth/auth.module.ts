import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserModule } from 'src/user/user.module';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/user/user.schema';
import { ActivationCodeHelper } from './helpers/activation-code.helper';
import { MailHelper } from './helpers/mail.helper';
import { PasswordResetCodeHelper } from './helpers/password-code.helper';
@Module({
  imports: [
    UserModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [
    AuthService,
    ActivationCodeHelper,
    MailHelper,
    PasswordResetCodeHelper,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
