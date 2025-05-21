import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Length } from 'class-validator';
import { Match } from './password-validator.dto';

export class SignUpDto {
  @ApiProperty({
    description: 'Full name of the user',
    minLength: 3,
    maxLength: 32,
    example: 'John Doe',
  })
  @IsString()
  @Length(3, 32)
  name: string;

  @ApiProperty({
    description: 'Email address of the user',
    example: 'john@example.com',
    minLength: 6,
    maxLength: 255,
  })
  @IsString()
  @Length(6, 255)
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Password for the user account',
    minLength: 8,
    maxLength: 255,
    example: 'StrongPassword123!',
  })
  @IsString()
  @Length(8, 255)
  password: string;

  @ApiProperty({
    description: 'Password confirmation (must match password)',
    minLength: 8,
    maxLength: 255,
    example: 'StrongPassword123!',
  })
  @IsString()
  @Length(8, 255)
  @Match('password')
  confirmPassword: string;
}
