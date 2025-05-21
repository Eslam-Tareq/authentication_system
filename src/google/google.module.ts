import { Module } from '@nestjs/common';
import { GoogleAuthService } from './google.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/user/user.schema';
import { JWTModule } from 'src/jwt/jwt.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    JWTModule,
  ],
  providers: [GoogleAuthService],
  exports: [GoogleAuthService],
})
export class GoogleModule {}
