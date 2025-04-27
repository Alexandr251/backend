import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { rateLimit } from 'express-rate-limit';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  app.use(helmet());

  // CORS настройки
  app.enableCors({
    origin: '*', //configService.get('FRONTEND_URL'),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Authorization'], // Для доступа к токенам на клиенте
  });

  // Rate limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 минут
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many requests, please try again later',
    }),
  );

  /*
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/api/csrf') return next();
    if (req.method === 'GET' || req.method === 'OPTIONS') return next();
    if (!req.headers['x-xsrf-token']) {
      return res.status(403).json({ message: 'CSRF token missing' });
    }
    next();
  });*/

  // Глобальная валидация
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Автоматически удаляет лишние поля
      forbidNonWhitelisted: true, // Бросает ошибку при лишних полях
    }),
  );

  await app.listen(configService.get('PORT') || 443);
  console.log(`Application is running on: ${await app.getUrl()}`);
}

bootstrap();
