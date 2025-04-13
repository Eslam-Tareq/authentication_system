import { IsString, Length } from 'class-validator';
import { Match } from './password-validator.dto';

export class ResetPasswordDto {
  @IsString()
  @Length(8, 255)
  newPassword: string;

  @IsString()
  @Length(8, 255)
  @Match('newPassword')
  confirmNewPassword: string;
}
