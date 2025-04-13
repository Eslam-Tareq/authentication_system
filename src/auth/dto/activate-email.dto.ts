import { IsString, Length } from 'class-validator';

export class ActivateEmailDto {
  @IsString()
  @Length(6)
  code: string;
}
