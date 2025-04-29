import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { WsException } from '@nestjs/websockets';

@Injectable()
export class WsJwtGuard implements CanActivate {
  private readonly logger = new Logger(WsJwtGuard.name);
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const client = context.switchToWs().getClient();
    const token = this.extractToken(client);

    if (!token) {
      this.logger.warn('No token provided');
      throw new WsException('Unauthorized: No token provided');
    }

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_SECRET'),
      });
      client.data.user = payload;
      return true;
    } catch (error) {
      this.logger.error(`JWT verification failed: ${error.message}`);
      throw new WsException('Unauthorized: Invalid token');
    }
  }

  private extractToken(client: any): string | null {
    return client.handshake.auth.token ||
      client.handshake.headers.authorization?.split(' ')[1] ||
      null;
  }

  /*
  canActivate(context: ExecutionContext): boolean {
    const client = context.switchToWs().getClient();
    const token = client.handshake.auth.token ||
      client.handshake.headers.authorization?.split(' ')[1];

    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_SECRET'),
      });
      client.data.user = payload;
      return true;
    } catch (error) {
      throw new WsException('Unauthorized');
    }
  }*/
}