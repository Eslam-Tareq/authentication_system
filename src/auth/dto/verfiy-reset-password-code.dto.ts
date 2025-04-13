import { IsString, Length } from 'class-validator';

export class VerifyResetPasswordCodeDto {
  @IsString()
  @Length(6, 6)
  code: string;
}
