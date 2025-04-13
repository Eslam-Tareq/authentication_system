import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Req,
  UseFilters,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CustomExceptionFilter } from 'src/common/filters/http-exception.filter';
import { AuthGuard } from 'src/auth/auth.guard';
import { ResponseDto } from 'src/common/filters/response.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  @Post()
  @UseGuards(AuthGuard)
  create(@Req() req: Request) {
    return (req as any).user;
  }
  @Get(':id')
  getOne(@Param('id', ParseIntPipe) id: number) {
    return this.userService.getById(id);
  }
  @Get()
  @UseGuards(AuthGuard)
  async getAll() {
    try {
      const result = await this.userService.getAll();
      return ResponseDto.success(result, 'users fetched successfully');
    } catch (err) {
      return ResponseDto.throwError(err.message, err.status);
    }
  }
}
