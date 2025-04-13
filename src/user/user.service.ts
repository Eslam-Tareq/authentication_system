import { Injectable } from '@nestjs/common';
import { User } from './user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name)
    private UserModel: Model<User>,
  ) {}
  create() {
    return 'User created successfully';
  }
  async getAll() {
    const users = await this.UserModel.find({});
    return users;
  }
  async getById(id: number) {
    return await this.UserModel.findById(id);
  }
  update(id: number) {
    return `User with id ${id} updated successfully`;
  }
  delete(id: number) {
    return `User with id ${id} deleted successfully`;
  }
}
