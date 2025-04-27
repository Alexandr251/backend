import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { MailModule } from './mail/mail.module';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import csurf from 'csurf';
import { CsrfController } from './auth/csrf.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    AuthModule,
    PrismaModule,
    MailModule,
  ],
  controllers: [CsrfController],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(helmet(), cookieParser(), csurf({ cookie: true }))
      .forRoutes('*');
  }
}
