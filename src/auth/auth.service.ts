import {
  Injectable,
  UnauthorizedException,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../mail/mail.service';
import { Response } from 'express';
import * as crypto from 'crypto';
import { randomBytes, createHash } from 'crypto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

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
    passwordBuffer.fill(0);

    if (!isMatch) {
      this.logger.warn(`Invalid password for: ${email}`);
      throw new UnauthorizedException('Неверный пароль');
    }
    if (!user.email_verified) {
      throw new UnauthorizedException('Email не подтверждён');
    }

    const { password_hash, verification_token, ...result } = user;
    return result;
  }

  async login(loginDto: LoginDto, res?: Response) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    const tokens = await this.generateTokens(user.id, user.email);

    if (res) {
      this.setRefreshTokenCookie(res, tokens.refresh_token);
    }

    return {
      access_token: tokens.access_token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
      },
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
        verification_token: verificationToken.hashedToken,
      },
    });

    await this.mailService.sendVerificationEmail(
      user.email,
      user.username,
      verificationToken.rawToken,
    );

    return { message: 'Письмо с подтверждением отправлено' };
  }

  async refreshTokens(refreshToken: string, res?: Response) {
    try {
      const tokenHash = crypto
        .createHash('sha256')
        .update(refreshToken)
        .digest('hex'); // генерацию измменить
      const tokenData = await this.prisma.refreshToken.findUnique({
        where: { token: tokenHash },
        include: { user: true },
      });

      if (!tokenData || tokenData.expires_at < new Date()) {
        throw new UnauthorizedException('Недействительный refresh-токен');
      }

      const tokens = await this.generateTokens(
        tokenData.user.id,
        tokenData.user.email,
      );

      // Удаляем использованный токен
      await this.prisma.refreshToken.delete({ where: { id: tokenData.id } });

      if (res) {
        this.setRefreshTokenCookie(res, tokens.refresh_token);
      }

      return {
        access_token: tokens.access_token,
        user: {
          id: tokenData.user.id,
          email: tokenData.user.email,
          username: tokenData.user.username,
        },
      };
    } catch (error) {
      this.logger.error(`Ошибка обновления токенов: ${error.message}`);
      throw new UnauthorizedException('Не удалось обновить токены');
    }
  }

  async logout(userId: number, res?: Response) {
    try {
      // Проверяем наличие активных сессий
      const activeSessions = await this.prisma.refreshToken.count({
        where: { user_id: userId },
      });

      if (activeSessions === 0) {
        this.logger.warn(`No active sessions to logout for user ${userId}`);
      }

      // Удаляем все refresh-токены пользователя
      const deleteResult = await this.prisma.refreshToken.deleteMany({
        where: { user_id: userId },
      });

      if (res) {
        res.clearCookie('refresh_token', {
          httpOnly: true,
          secure: this.configService.get('NODE_ENV') === 'production',
          sameSite: 'strict',
          path: '/api/auth',
        });
      }

      return {
        message: 'Успешный выход из системы',
        sessionsTerminated: deleteResult.count,
      };
    } catch (error) {
      this.logger.error(`Ошибка выхода: ${error.message}`);
      throw new UnauthorizedException('Не удалось выйти из системы');
    }
  }

  private async generateTokens(userId: number, email: string) {
    const payload = { email, sub: userId };
    const refreshExpireDays = parseInt(
      this.configService.get<string>('JWT_REFRESH_EXPIRE', '7'), // '7' - значение по умолчанию
    );
    const expiresAt = new Date(
      Date.now() + refreshExpireDays * 24 * 60 * 60 * 1000,
    );

    const access_token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRE'),
    });

    const refresh_token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRE'),
    });

    const refreshTokenHash = crypto
      .createHash('sha256')
      .update(refresh_token)
      .digest('hex');
    // Сохраняем refresh-токен в БД
    await this.prisma.refreshToken.create({
      data: {
        token: refreshTokenHash,
        user_id: userId,
        expires_at: expiresAt,
      },
    });

    return { access_token, refresh_token };
  }

  private setRefreshTokenCookie(res: Response, token: string) {
    res.cookie('refresh_token', token, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      path: '/api/auth',
      maxAge:
        parseInt(this.configService.get('JWT_REFRESH_EXPIRE').slice(0, -1)) *
        24 *
        60 *
        60 *
        1000,
      priority: 'high'
    });
  }


  async verifyEmail(token: string) {
    // Хешируем токен для поиска
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await this.prisma.user.findFirst({
      where: {
        verification_token: tokenHash,
        email_verified: false
      }
    });

    if (!user) {
      // Проверяем случаи:
      // 1. Токен неверный
      // 2. Email уже верифицирован
      const existingUser = await this.prisma.user.findFirst({
        where: { verification_token: tokenHash }
      });

      if (existingUser?.email_verified) {
        throw new BadRequestException('Email уже подтверждён');
      }
      throw new UnauthorizedException('Неверный токен подтверждения');
    }

    // Обновляем запись пользователя
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        email_verified: true,
        verification_token: null,
      },
    });
  }

  /*
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
  }*/

  private generateVerificationToken(): {
    rawToken: string;
    hashedToken: string;
  } {
    const rawToken = randomBytes(32).toString('hex');
    const hashedToken = createHash('sha256').update(rawToken).digest('hex');

    return {
      rawToken, // Для отправки по email
      hashedToken, // Для хранения в БД
    };
  }

  /*
  private generateVerificationToken(): string {
    return require('crypto').randomBytes(32).toString('hex');
  }*/
}
