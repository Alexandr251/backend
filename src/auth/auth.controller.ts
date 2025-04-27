import { Controller, Post, Body, Get, Query, Res, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Public } from '../common/decorators/public.decorator';
import { Throttle } from '@nestjs/throttler';
import { Response, Request } from 'express';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import { AuthRequest } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.authService.login(loginDto, res);
  }

  @Public()
  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 запроса в минуту
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    // Искусственная задержка 1 секунда
    await new Promise(resolve => setTimeout(resolve, 1000));
    return this.authService.register(registerDto);
  }

  @Public()
  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const refreshToken = req.cookies?.refresh_token || req.body?.refresh_token;
    return this.authService.refreshTokens(refreshToken, res);
  }

  @Post('logout')
  async logout(
    @Req() req: AuthRequest,
    @Res({ passthrough: true }) res: Response
  ) {
    const userId = req.user?.userId;
    return this.authService.logout(userId, res);
  }
}
