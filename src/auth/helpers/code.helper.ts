import { Injectable } from '@nestjs/common';
import { UserDocument } from 'src/user/user.schema';
import * as crypto from 'crypto';
export const generateCode = () => {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  return code;
};
export const sha256Hashing = (objective: string) => {
  return crypto.createHash('sha256').update(objective).digest('hex');
};

export const generateSecureToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

export const resettingUserCodeFields = async (user: UserDocument) => {
  user.activationCode = undefined;
  user.activationCodeExpiresIn = undefined;
  user.activationToken = undefined;
  user.passwordResetCode = undefined;
  user.passwordResetVerificationToken = undefined;
  user.passwordResetCodeExpires = undefined;
  user.passwordResetToken = undefined;
  await user.save();
};
