import * as bcrypt from 'bcrypt';

export const hashingPassword = async (password: string) => {
  const hashedPassword = await bcrypt.hash(password, 12);
  return hashedPassword;
};

export const isCorrectPassword = async (
  enteredPass: string,
  realPass: string,
) => {
  return await bcrypt.compare(enteredPass, realPass);
};
