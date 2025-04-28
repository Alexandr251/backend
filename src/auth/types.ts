import { JwtPayload } from './strategies/jwt.strategy';

export interface AuthRequest extends Request {
  user: JwtPayload; // Используем единый тип
}

/*
import { Request } from 'express';

export interface AuthRequest extends Request {
  user: {
    userId: number;
    email: string;
  };
}*/