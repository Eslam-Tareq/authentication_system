import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length } from 'class-validator';
import { Match } from './password-validator.dto';

export class ResetPasswordDto {
  @ApiProperty({
    description: 'New password for the account (8–255 characters)',
    minLength: 8,
    maxLength: 255,
    example: 'NewSecurePass123!',
  })
  @IsString()
  @Length(8, 255)
  newPassword: string;

  @ApiProperty({
    description: 'Confirmation of the new password (must match newPassword)',
    minLength: 8,
    maxLength: 255,
    example: 'NewSecurePass123!',
  })
  @IsString()
  @Length(8, 255)
  @Match('newPassword')
  confirmNewPassword: string;
}
