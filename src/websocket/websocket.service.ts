import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Server } from 'socket.io';

@Injectable()
export class WebSocketService {
  private server: Server;

  constructor(private prisma: PrismaService) {}

  setServer(server: Server) {
    this.server = server;
  }

  async getUserRooms(userId: number) {
    const memberships = await this.prisma.chatMember.findMany({
      where: { user_id: userId },
      select: { chat_id: true },
    });
    return memberships.map(m => `chat_${m.chat_id}`);
  }
  async markAsRead(userId: number, messageId: bigint) {
    await this.prisma.readReceipt.upsert({
      where: {
        message_id_user_id: {
          message_id: messageId,
          user_id: userId,
        },
      },
      create: {
        message_id: messageId,
        user_id: userId,
      },
      update: {
        read_at: new Date(),
      },
    });
  }

  async getUnreadCount(userId: number) {
    const chats = await this.prisma.chatMember.findMany({
      where: { user_id: userId },
      select: { chat_id: true },
    });

    const counts = await this.prisma.message.groupBy({
      by: ['chat_id'],
      where: {
        chat_id: { in: chats.map(c => c.chat_id) },
        NOT: {
          read_receipts: {
            some: {
              user_id: userId,
            },
          },
        },
      },
      _count: { _all: true },
    });

    return counts;
  }

  async notifyUser(userId: number, event: string, data: any) {
    const userSockets = await this.server.fetchSockets();
    const userSocket = userSockets.find(s => s.data.userId === userId);
    if (userSocket) {
      userSocket.emit(event, data);
    }
  }

  /*
  async notifyUser(userId: number, event: string, data: any) {
    const userSockets = await this.server.fetchSockets();
    const userSocket = userSockets.find((s) => s.data.userId === userId);
    if (userSocket) {
      userSocket.emit(event, data);
    }
  }*/


  /*
  async markAsRead(userId: number, messageId: bigint) {
    await this.prisma.unreadMessage.deleteMany({
      where: {
        user_id: userId,
        message_id: messageId,
      },
    });
  }

  async getUnreadCount(userId: number) {
    return this.prisma.unreadMessage.groupBy({
      by: ['chat_id'],
      where: { user_id: userId },
      _count: { _all: true },
    });
  }*/
}