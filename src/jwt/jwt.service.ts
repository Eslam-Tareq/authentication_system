import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { UserDocument } from 'src/user/user.schema';

@Injectable()
export class TokenService {
  constructor(private readonly jwtService: JwtService) {}
  generateAccessToken(user: UserDocument) {
    const payload = {
      _id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
    };
    const accessToken = this.jwtService.sign(payload);
    return accessToken;
  }

  extractTokenFromRequest(request: Request) {
    let token: string;
    if (
      request.headers.authorization &&
      request.headers.authorization.startsWith('Bearer')
    ) {
      token = request.headers.authorization.split(' ')[1];
    } else {
      token = request.cookies?.accessToken;
    }
    return token;
  }
}
