import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
  @Prop({ type: String, trim: true, required: [true, 'user must have a name'] })
  name: String;
  @Prop({
    type: String,
    lowercase: true,
  })
  slug: String;
  @Prop({
    type: String,
    required: [true, 'user must have a email'],
    unique: true,
    lowercase: true,
    trim: true,
  })
  email: String;
  @Prop({
    type: String,
    required: [true, 'user must have a password'],
    minlength: [6, 'password must have at least 8 characters'],
  })
  password: string;
  @Prop()
  passwordChangedAt: Date;
  @Prop()
  passwordResetCode: string;
  @Prop()
  passwordResetCodeExpires: Date;
  @Prop()
  passwordResetVerificationToken: string;
  @Prop()
  passwordResetToken: string;
  @Prop({
    type: String,
    default: 'user',
    enum: ['user', 'admin', 'manager'],
  })
  role: string;
  @Prop()
  profileImg: string;
  @Prop()
  phoneNumber: string;
  @Prop({
    type: Date,
    index: { expireAfterSeconds: 10 },
  })
  expireAt: Date;
  @Prop({
    type: Boolean,
    default: false,
  })
  isActivated: boolean;
  @Prop()
  activationCode: String;
  @Prop()
  activationCodeExpiresIn: Date;
  @Prop()
  activationToken: String;
}

export const UserSchema = SchemaFactory.createForClass(User);
