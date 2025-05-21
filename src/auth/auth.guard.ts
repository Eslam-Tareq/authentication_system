import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    let token: string;
    if (
      request.headers.authorization &&
      request.headers.authorization.startsWith('Bearer')
    ) {
      token = request.headers.authorization.split(' ')[1];
    } else {
      token = request.cookies.accessToken;
    }
    if (!token) {
      return false;
    }
    let decoded: any;
    try {
      decoded = this.jwtService.verify(token);
    } catch (err) {
      return false;
    }
    const user = await this.userService.getById(decoded!._id);
    if (!user) {
      return false;
    }

    if (user.passwordChangedAt) {
      const passChangedAtTimeStamp = parseInt(
        `${user.passwordChangedAt.getTime() / 1000}`,
        10,
      );

      if (passChangedAtTimeStamp > decoded!.iat!) {
        return false;
      }
    }
    request.user = user;
    return true;
  }
}
