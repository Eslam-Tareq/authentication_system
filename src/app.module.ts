import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { APP_FILTER } from '@nestjs/core';
import { CatchEverythingFilter } from './common/filters/custom-exception.filter';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { GoogleModule } from './google/google.module';
import { JWTModule } from './jwt/jwt.module';
import { NodeMailer } from './config/node-mailer.config';
import { MongodbModule } from './config/mongodb.module';
@Module({
  imports: [
    ConfigModule.forRoot(),
    MongodbModule,
    UserModule,
    AuthModule,
    GoogleModule,
    JWTModule,
    NodeMailer,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_FILTER,
      useClass: CatchEverythingFilter,
    },
  ],
})
export class AppModule {}
