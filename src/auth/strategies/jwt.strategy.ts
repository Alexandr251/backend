import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';

export interface JwtPayload {
  sub: number; // userID
  email: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private prisma: PrismaService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (req) => req?.cookies?.access_token, // Для cookie-варианта
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET') as string, // Явное приведение типа
    });
  }

  async validate(payload: JwtPayload) {
    // Проверяем, что пользователь существует и активен
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, is_online: true, email_verified: true }
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.email_verified) {
      throw new UnauthorizedException('Email not verified');
    }


    return { userId: user.id, email: user.email };
  }
}
