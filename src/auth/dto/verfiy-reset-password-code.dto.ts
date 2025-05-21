import { IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyResetPasswordCodeDto {
  @ApiProperty({
    description:
      '6-digit verification code sent to the user for password reset',
    example: '654321',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @Length(6, 6)
  code: string;
}
