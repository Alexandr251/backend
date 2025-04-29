import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { MailModule } from './mail/mail.module';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { ThrottlerModule } from '@nestjs/throttler';
import { WebSocketModule } from './websocket/websocket.module';
import { ChatGateway } from './chat/chat.gateway';
import { ChatModule } from './chat/chat.module';
import { APP_GUARD } from '@nestjs/core';
import { WsJwtGuard } from './websocket/guards/ws-jwt.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    AuthModule,
    PrismaModule,
    MailModule,
    WebSocketModule,
    ChatModule,
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60000, // В миллисекундах (60 секунд)
          limit: 10,
        },
      ],
    }),
  ],
  providers: [ ChatGateway,
    { provide: APP_GUARD, useClass: WsJwtGuard }],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(helmet(), cookieParser())
      .forRoutes('*path'); // было: '*'
  }
}
