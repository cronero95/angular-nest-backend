
import { Injectable, BadRequestException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from "bcryptjs";

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,

    private jwtService: JwtService,
  ){}

   async create(createUserDto: CreateUserDto): Promise<User> {
    try{
      const {password, ...userData} = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const {password: _, ...user} = newUser.toJSON();

      return user;

    } catch(error) {

      if(error.code === 11000) {
        throw new BadRequestException(`The email ${createUserDto.email} has already been used`)
      } else {
        throw new InternalServerErrorException('Something terrible has happened')
      }
      
    }
  }

  async register(registerDto: RegisterDto): Promise<LoginResponse> {

    const {password, password2, email, name} = registerDto;

    if(password !== password2) {
      throw new BadRequestException(`The password must be the same!!`);
    }

    await this.create({password, email, name});

    return this.login({password, email});
    

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const {password, email} = loginDto

    const user = await this.userModel.findOne({email});
    if(!user) {
      throw new UnauthorizedException(`Not valid credentials - email`)
    }

    if(!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException(`Not valid credentials - password`)
    }

    const {password: _, ...userResp} = user.toJSON();

    return {
      user: userResp,
      token: this.getJwToken({id: user.id}),
    };

  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
