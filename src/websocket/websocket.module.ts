import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { WebSocketService } from './websocket.service';
import { ChatGateway } from '../chat/chat.gateway';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthModule } from '../auth/auth.module';
import { WsJwtGuard } from './guards/ws-jwt.guard';

@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: configService.get('JWT_ACCESS_EXPIRE') },
      }),
      inject: [ConfigService],
    }),
    ConfigModule,
    PrismaModule,
    AuthModule,
  ],
  providers: [WebSocketService, ChatGateway, WsJwtGuard],
  exports: [WebSocketService, ChatGateway],
})
export class WebSocketModule {}