import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { UseGuards, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { WsJwtGuard } from '../websocket/guards/ws-jwt.guard';
import { WebSocketService } from '../websocket/websocket.service';
import { WsException } from '@nestjs/websockets';

@WebSocketGateway({
  cors: {
    origin: '*',
    credentials: true,
  },
  namespace: 'chat',
})
@UseGuards(WsJwtGuard) // Применяем guard ко всем обработчикам
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;
  private readonly logger = new Logger(ChatGateway.name);

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private prisma: PrismaService,
    private webSocketService: WebSocketService,
  ) {}

  afterInit(server: Server) {
    this.webSocketService.setServer(server);
  }

  async handleConnection(client: Socket) {
    try {
      const authToken = client.handshake.auth.token || client.handshake.headers.authorization;
      const payload = this.jwtService.verify(authToken, {
        secret: this.configService.get('JWT_SECRET'),
      });

      const user = await this.prisma.user.update({
        where: { id: payload.sub },
        data: { is_online: true },
      });

      // Сохраняем событие подключения
      await this.prisma.connectionEvent.create({
        data: {
          user_id: user.id,
          event_type: 'connect',
          ip_address: client.handshake.address,
        },
      });

      // Уведомляем всех о новом подключении
      this.server.emit('user_connected', {
        userId: user.id,
        username: user.username,
      });

      // Присоединяем клиента к его личным комнатам
      const userChats = await this.prisma.chatMember.findMany({
        where: { user_id: user.id },
        select: { chat_id: true },
      });

      userChats.forEach((chat) => {
        client.join(`chat_${chat.chat_id}`);
      });

      // Также присоединяем к персональной комнате для уведомлений
      client.join(`user_${user.id}`);

      client.data.userId = user.id;
    } catch (error) {
      this.logger.error(`Connection error: ${error.message}`);
      client.disconnect(true);
    }
  }

  async handleDisconnect(client: Socket) {
    if (!client.data.userId) return;

    try {
      const user = await this.prisma.user.update({
        where: { id: client.data.userId },
        data: { is_online: false },
      });

      // Сохраняем событие отключения
      await this.prisma.connectionEvent.create({
        data: {
          user_id: user.id,
          event_type: 'disconnect',
          ip_address: client.handshake.address,
        },
      });

      this.server.emit('user_disconnected', {
        userId: user.id,
        username: user.username,
      });
    } catch (error) {
      this.logger.error(`Disconnection error: ${error.message}`);
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('send_message')
  async handleMessage(
    @MessageBody() data: { chatId: number; content: string; attachments?: Array<{
        path: string;
        originalName: string;
        mimeType: string;
        size: number;
      }> },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // 1. Валидация входных данных
      if (!data.chatId || !data.content?.trim()) {
        throw new WsException('Chat ID and message content are required');
      }

      // 2. Проверка прав доступа к чату
      const isMember = await this.prisma.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: data.chatId,
            user_id: client.data.userId,
          },
        },
      });

      if (!isMember) {
        throw new WsException('You are not a member of this chat');
      }

      // 3. Создание сообщения в БД
      const message = await this.prisma.message.create({
        data: {
          content: data.content,
          chat_id: data.chatId,
          sender_id: client.data.userId,
          attachments: data.attachments?.length ? {
            createMany: {
              data: data.attachments.map(att => ({
                file_path: att.path,
                original_name: att.originalName,
                mime_type: att.mimeType,
                file_size: att.size,
              })),
            },
          } : undefined,
        },
        include: {
          sender: {
            select: {
              id: true,
              username: true,
              avatar_path: true,
            },
          },
          attachments: true,
        },
      });

      if (!message.sender) {
        throw new WsException('Failed to create message: sender not found');
      }

      // 4. Обновление времени последней активности чата
      await this.prisma.chat.update({
        where: { id: data.chatId },
        data: { last_activity: new Date() },
      });

      // 5. Автоматически отмечаем как прочитанное для отправителя
      await this.prisma.readReceipt.create({
        data: {
          message_id: message.id,
          user_id: client.data.userId,
        },
      });

      // 6. Формируем ответ для отправки клиентам
      const response = {
        id: message.id,
        content: message.content,
        createdAt: message.created_at,
        isSystem: message.is_system,
        sender: {
          id: message.sender.id,
          username: message.sender.username,
          avatar: message.sender.avatar_path,
        },
        attachments: message.attachments,
        readBy: [client.data.userId],
      };

      // 7. Отправка сообщения участникам чата
      this.server.to(`chat_${data.chatId}`).emit('new_message', response);

      // 8. Получаем список участников чата для уведомлений
      const chatMembers = await this.prisma.chatMember.findMany({
        where: { chat_id: data.chatId },
        select: { user_id: true },
      });

      // 9. Отправка уведомлений о непрочитанных сообщениях
      const recipients = chatMembers
        .filter(m => m.user_id !== client.data.userId)
        .map(m => m.user_id);

      if (recipients.length > 0) {
        await this.prisma.readReceipt.createMany({
          data: recipients.map(userId => ({
            message_id: message.id,
            user_id: userId,
          })),
          skipDuplicates: true,
        });

        // Отправляем уведомления
        recipients.forEach(userId => {
          this.server.to(`user_${userId}`).emit('unread_message', {
            chatId: data.chatId,
            messageId: message.id,
            senderId: client.data.userId,
          });
        });
      }

      return { status: 'success', messageId: message.id };
    } catch (error) {
      this.logger.error(`Message sending error: ${error.message}`);
      throw new WsException(
        error instanceof WsException
          ? error.message
          : 'Failed to send message'
      );
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('mark_as_read')
  async handleMarkAsRead(
    @MessageBody() data: { messageId: bigint },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // 1. Проверяем что сообщение существует
      const message = await this.prisma.message.findUnique({
        where: { id: data.messageId },
        include: { chat: true },
      });

      if (!message) {
        throw new WsException('Message not found');
      }

      // 2. Проверяем что пользователь состоит в чате
      const isMember = await this.prisma.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: message.chat_id,
            user_id: client.data.userId,
          },
        },
      });

      if (!isMember) {
        throw new WsException('You are not a member of this chat');
      }

      // 3. Создаем или обновляем запись о прочтении
      await this.prisma.readReceipt.upsert({
        where: {
          message_id_user_id: {
            message_id: data.messageId,
            user_id: client.data.userId,
          },
        },
        create: {
          message_id: data.messageId,
          user_id: client.data.userId,
        },
        update: {
          read_at: new Date(),
        },
      });

      // 4. Уведомляем других участников чата
      this.server.to(`chat_${message.chat_id}`).emit('message_read', {
        messageId: data.messageId,
        userId: client.data.userId,
        readAt: new Date(),
      });

      return { status: 'success' };
    } catch (error) {
      this.logger.error(`Mark as read error: ${error.message}`);
      throw new WsException(
        error instanceof WsException
          ? error.message
          : 'Failed to mark message as read'
      );
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('typing')
  async handleTyping(
    @MessageBody() data: { chatId: number, isTyping: boolean },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // Проверяем что пользователь состоит в чате
      const isMember = await this.prisma.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: data.chatId,
            user_id: client.data.userId,
          },
        },
        include: { user: { select: { username: true } } },
      });

      if (!isMember || !isMember.user) {
        throw new WsException('You are not a member of this chat');
      }

      // Отправляем уведомление другим участникам чата
      this.server.to(`chat_${data.chatId}`).emit('user_typing', {
        userId: client.data.userId,
        username: isMember.user.username,
        chatId: data.chatId,
        isTyping: data.isTyping,
      });

      return { status: 'success' };
    } catch (error) {
      this.logger.error(`Typing notification error: ${error.message}`);
      throw new WsException('Failed to send typing notification');
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('get_unread')
  async handleGetUnread(
    @ConnectedSocket() client: Socket,
  ) {
    try {
      const counts = await this.webSocketService.getUnreadCount(client.data.userId);
      return { status: 'success', counts };
    } catch (error) {
      this.logger.error(`Error getting unread count: ${error.message}`);
      throw new WsException('Error getting unread messages');
    }
  }
}


/*
import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { UseGuards, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { WsJwtGuard } from '../websocket/guards/ws-jwt.guard';
import { WebSocketService } from '../websocket/websocket.service';
import { WsException } from '@nestjs/websockets';

@WebSocketGateway({
  cors: {
    origin: '*',
    credentials: true,
  },
  namespace: 'chat',
})
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;
  private readonly logger = new Logger(ChatGateway.name);

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private prisma: PrismaService,
    private webSocketService: WebSocketService,
  ) {}

  afterInit(server: Server) {
    this.webSocketService.setServer(server);
  }

  async handleConnection(client: Socket) {
    try {
      const authToken = client.handshake.auth.token || client.handshake.headers.authorization;
      const payload = this.jwtService.verify(authToken, {
        secret: this.configService.get('JWT_SECRET'),
      });

      const user = await this.prisma.user.update({
        where: { id: payload.sub },
        data: { is_online: true },
      });

      // Сохраняем событие подключения
      await this.prisma.connectionEvent.create({
        data: {
          user_id: user.id,
          event_type: 'connect',
          ip_address: client.handshake.address,
        },
      });

      // Уведомляем всех о новом подключении
      this.server.emit('user_connected', {
        userId: user.id,
        username: user.username,
      });

      // Присоединяем клиента к его личным комнатам
      const userChats = await this.prisma.chatMember.findMany({
        where: { user_id: user.id },
        select: { chat_id: true },
      });

      userChats.forEach((chat) => {
        client.join(`chat_${chat.chat_id}`);
      });

      client.data.userId = user.id;
    } catch (error) {
      this.logger.error(`Connection error: ${error.message}`);
      client.disconnect(true);
    }
  }

  async handleDisconnect(client: Socket) {
    if (!client.data.userId) return;

    try {
      const user = await this.prisma.user.update({
        where: { id: client.data.userId },
        data: { is_online: false },
      });

      // Сохраняем событие отключения
      await this.prisma.connectionEvent.create({
        data: {
          user_id: user.id,
          event_type: 'disconnect',
          ip_address: client.handshake.address,
        },
      });

      this.server.emit('user_disconnected', {
        userId: user.id,
        username: user.username,
      });
    } catch (error) {
      this.logger.error(`Disconnection error: ${error.message}`);
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('send_message')
  async handleMessage(
    @MessageBody() data: { chatId: number; content: string; attachments?: any[] },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // 1. Валидация входных данных
      if (!data.chatId || !data.content?.trim()) {
        throw new WsException('Chat ID and message content are required');
      }

      // 2. Проверка прав доступа к чату
      const isMember = await this.prisma.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: data.chatId,
            user_id: client.data.userId,
          },
        },
      });

      if (!isMember) {
        throw new WsException('You are not a member of this chat');
      }

      // 3. Создание сообщения в БД
      const message = await this.prisma.message.create({
        data: {
          content: data.content,
          chat_id: data.chatId,
          sender_id: client.data.userId,
          attachments: data.attachments?.length ? {
            createMany: {
              data: data.attachments.map(att => ({
                file_path: att.path,
                original_name: att.originalName,
                mime_type: att.mimeType,
                file_size: att.size,
              })),
            },
          } : undefined,
        },
        include: {
          sender: {
            select: {
              id: true,
              username: true,
              avatar_path: true,
            },
          },
          attachments: true,
        },
      });

      // 4. Обновление времени последней активности чата
      await this.prisma.chat.update({
        where: { id: data.chatId },
        data: { last_activity: new Date() },
      });

      // 5. Создание записей о прочтении (read receipts)
      const chatMembers = await this.prisma.chatMember.findMany({
        where: { chat_id: data.chatId },
        select: { user_id: true },
      });

      // Автоматически отмечаем как прочитанное для отправителя
      await this.prisma.readReceipt.create({
        data: {
          message_id: message.id,
          user_id: client.data.userId,
        },
      });

      // 6. Отправка сообщения участникам чата
      const response = {
        id: message.id,
        content: message.content,
        createdAt: message.created_at,
        isSystem: message.is_system,
        sender: {
          id: message.sender.id,
          username: message.sender.username,
          avatar: message.sender.avatar_path,
        },
        attachments: message.attachments,
        readBy: [client.data.userId], // Сразу отмечаем как прочитанное отправителем
      };

      this.server.to(`chat_${data.chatId}`).emit('new_message', response);

      // 7. Отправка уведомлений о непрочитанных сообщениях
      const recipients = chatMembers
        .filter(m => m.user_id !== client.data.userId)
        .map(m => m.user_id);

      if (recipients.length > 0) {
        await this.prisma.readReceipt.createMany({
          data: recipients.map(userId => ({
            message_id: message.id,
            user_id: userId,
          })),
          skipDuplicates: true,
        });

        // Отправляем уведомления
        recipients.forEach(userId => {
          this.server.to(`user_${userId}`).emit('unread_message', {
            chatId: data.chatId,
            messageId: message.id,
          });
        });
      }

      return { status: 'success', messageId: message.id };
    } catch (error) {
      this.logger.error(`Message sending error: ${error.message}`);
      throw new WsException(
        error instanceof WsException
          ? error.message
          : 'Failed to send message'
      );
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('mark_as_read')
  async handleMarkAsRead(
    @MessageBody() data: { messageId: bigint },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      await this.webSocketService.markAsRead(client.data.userId, data.messageId);
      // 1. Проверяем что сообщение существует
      const message = await this.prisma.message.findUnique({
        where: { id: data.messageId },
        include: { chat: true },
      });

      if (!message) {
        throw new WsException('Message not found');
      }

      // 2. Проверяем что пользователь состоит в чате
      const isMember = await this.prisma.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: message.chat_id,
            user_id: client.data.userId,
          },
        },
      });

      if (!isMember) {
        throw new WsException('You are not a member of this chat');
      }

      // 3. Создаем или обновляем запись о прочтении
      await this.prisma.readReceipt.upsert({
        where: {
          message_id_user_id: {
            message_id: data.messageId,
            user_id: client.data.userId,
          },
        },
        create: {
          message_id: data.messageId,
          user_id: client.data.userId,
        },
        update: {
          read_at: new Date(),
        },
      });

      // 4. Уведомляем других участников чата
      this.server.to(`chat_${message.chat_id}`).emit('message_read', {
        messageId: data.messageId,
        userId: client.data.userId,
        readAt: new Date(),
      });

      return { status: 'success' };
    } catch (error) {
      this.logger.error(`Mark as read error: ${error.message}`);
      throw new WsException(
        error instanceof WsException
          ? error.message
          : 'Failed to mark message as read'
      );
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('typing')
  async handleTyping(
    @MessageBody() data: { chatId: number, isTyping: boolean },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      // Проверяем что пользователь состоит в чате
      const isMember = await this.prisma.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: data.chatId,
            user_id: client.data.userId,
          },
        },
        select: { user: { select: { username: true } } },
      });

      if (!isMember) {
        throw new WsException('You are not a member of this chat');
      }

      // Отправляем уведомление другим участникам чата
      this.server.to(`chat_${data.chatId}`).emit('user_typing', {
        userId: client.data.userId,
        username: isMember.user.username,
        chatId: data.chatId,
        isTyping: data.isTyping,
      });

      return { status: 'success' };
    } catch (error) {
      this.logger.error(`Typing notification error: ${error.message}`);
      throw new WsException('Failed to send typing notification');
    }
  }

  @UseGuards(WsJwtGuard)
  @SubscribeMessage('get_unread')
  async handleGetUnread(
    @ConnectedSocket() client: Socket,
  ) {
    try {
      const counts = await this.webSocketService.getUnreadCount(client.data.userId);
      return { status: 'success', counts };
    } catch (error) {
      this.logger.error(`Error getting unread count: ${error.message}`);
      throw new WsException('Error getting unread messages');
    }
  }
}*/