import { IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ActivateEmailDto {
  @ApiProperty({
    description: 'Activation code sent to the user email',
    example: '123456',
    minLength: 6,
  })
  @IsString()
  @Length(6)
  code: string;
}
