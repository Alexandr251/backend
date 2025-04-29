import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { MailModule } from '../mail/mail.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  imports: [
    PrismaModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: configService.get('JWT_ACCESS_EXPIRE') },
      }),
      inject: [ConfigService],
    }),
    ConfigModule,
    MailModule,
    ThrottlerModule.forRoot({
      throttlers: [{
        ttl: 60000, // В миллисекундах (60 секунд)
        limit: 10,
      }]
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    RefreshTokenGuard,
    JwtAuthGuard,
    {
      provide: 'APP_GUARD',
      useClass: JwtAuthGuard, // Глобальная регистрация guard'а
  }],
  exports: [JwtModule, AuthService, JwtAuthGuard],
})
export class AuthModule {}
