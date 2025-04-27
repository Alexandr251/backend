import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../mail/mail.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
  ) {}

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('Пользователь не найден');

    const passwordBuffer = Buffer.from(pass, 'utf-8');
    const isMatch = await bcrypt.compare(passwordBuffer, user.password_hash);
    passwordBuffer.fill(0); // Очищаем буфер
    if (!isMatch) throw new UnauthorizedException('Неверный пароль');

    if (!user.email_verified) {
      throw new UnauthorizedException('Email не подтвержден');
    }

    const { password_hash, verification_token, ...result } = user;
    return result;
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    const payload = { email: user.email, sub: user.id };

    return {
      access_token: this.jwtService.sign(payload, {
        secret: this.configService.get('JWT_SECRET'),
        expiresIn: '15m',
      }),
      refresh_token: this.jwtService.sign(payload, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    };
  }

  async register(registerDto: RegisterDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: registerDto.email },
    });

    if (existingUser) {
      throw new UnauthorizedException(
        'Пользователь с таким email уже существует',
      );
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    const verificationToken = this.generateVerificationToken();

    const user = await this.prisma.user.create({
      data: {
        email: registerDto.email,
        password_hash: hashedPassword,
        username: registerDto.username,
        verification_token: verificationToken,
      },
    });

    // Отправляем email с подтверждением
    await this.mailService.sendVerificationEmail(
      user.email,
      user.username,
      verificationToken,
    );

    const { password_hash, verification_token: _, ...result } = user;
    return result;
  }

  async verifyEmail(token: string) {
    const user = await this.prisma.user.findFirst({
      where: { verification_token: token },
    });

    if (!user) {
      throw new UnauthorizedException('Неверный токен подтверждения');
    }

    return this.prisma.user.update({
      where: { id: user.id },
      data: {
        email_verified: true,
        verification_token: null,
      },
    });
  }

  private generateVerificationToken(): string {
    return require('crypto').randomBytes(32).toString('hex');
  }
}
