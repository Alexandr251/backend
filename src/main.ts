import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { rateLimit } from 'express-rate-limit';
import { ValidationPipe } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(helmet());

  // CORS настройки
  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'Authorization'],
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
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/api/csrf') return next();
    if (req.method === 'GET' || req.method === 'OPTIONS') return next();
    if (!req.headers['x-xsrf-token']) {
      return res.status(403).json({ message: 'CSRF token missing' });
    }
    next();
  });

  // Глобальная валидация
  app.useGlobalPipes(new ValidationPipe());

  await app.listen(process.env.PORT || 443);
  console.log(`Application is running on: ${await app.getUrl()}`);
}

bootstrap();
