import {
  IsEmail,
  IsOptional,
  IsPhoneNumber,
  IsString,
  Length,
} from 'class-validator';
import { Match } from './password-validator.dto';

export class SignUpDto {
  @IsString()
  @Length(3, 32)
  name: string;
  @IsString()
  @Length(6, 255)
  @IsEmail()
  email: string;
  @IsString()
  @Length(8, 255)
  password: string;
  @IsString()
  @Length(8, 255)
  @Match('password')
  confirmPassword: string;
  @IsOptional()
  @IsString()
  profileImg?: string;
  @IsOptional()
  @IsPhoneNumber()
  phoneNumber?: string;
}
