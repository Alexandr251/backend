import { Injectable, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateChatDto } from './dto/create-chat.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { PaginationDto } from '../common/dto/pagination.dto';

@Injectable()
export class ChatService {
  constructor(private prisma: PrismaService) {}

  async createChat(userId: number, dto: CreateChatDto) {
    return this.prisma.$transaction(async (tx) => {
      const chat = await tx.chat.create({
        data: {
          chat_type: dto.chatType,
          chat_name: dto.chatName,
          created_by_id: userId,
        },
      });

      await tx.chatMember.createMany({
        data: [
          { chat_id: chat.id, user_id: userId, is_admin: true },
          ...dto.members.map(memberId => ({
            chat_id: chat.id,
            user_id: memberId,
            is_admin: false,
          })),
        ],
      });

      return chat;
    });
  }

  async sendMessage(userId: number, dto: SendMessageDto) {
    return this.prisma.$transaction(async (tx) => {
      const isMember = await tx.chatMember.findUnique({
        where: {
          chat_id_user_id: {
            chat_id: dto.chatId,
            user_id: userId,
          },
        },
      });

      if (!isMember) {
        throw new ForbiddenException('Access to chat denied');
      }

      const message = await tx.message.create({
        data: {
          content: dto.content,
          chat_id: dto.chatId,
          sender_id: userId,
          attachments: dto.attachments?.length ? {
            createMany: {
              data: dto.attachments.map(att => ({
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

      await tx.chat.update({
        where: { id: dto.chatId },
        data: { last_activity: new Date() },
      });

      return message;
    });
  }

  async getMessages(userId: number, chatId: number, pagination: PaginationDto) {
    const page = pagination.page || 1;
    const limit = pagination.limit || 20;

    const isMember = await this.prisma.chatMember.findUnique({
      where: {
        chat_id_user_id: {
          chat_id: chatId,
          user_id: userId,
        },
      },
    });

    if (!isMember) {
      throw new ForbiddenException('Access to chat denied');
    }

    return this.prisma.message.findMany({
      where: { chat_id: chatId },
      include: {
        sender: {
          select: {
            id: true,
            username: true,
            avatar_path: true,
          },
        },
        attachments: true,
        read_receipts: {
          where: { user_id: userId },
          select: { read_at: true },
        },
      },
      orderBy: { created_at: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    });
  }

  async deleteMessage(userId: number, messageId: bigint) {
    const message = await this.prisma.message.findUnique({
      where: { id: messageId },
      include: { sender: true },
    });

    if (!message) {
      throw new NotFoundException('Message not found');
    }

    if (message.sender_id !== userId) {
      throw new ForbiddenException('You can only delete your own messages');
    }

    return this.prisma.message.delete({
      where: { id: messageId },
    });
  }

  async getUserChats(userId: number) {
    return this.prisma.chatMember.findMany({
      where: { user_id: userId },
      include: {
        chat: {
          include: {
            messages: {
              orderBy: { created_at: 'desc' },
              take: 1,
              include: {
                sender: {
                  select: {
                    username: true,
                  },
                },
              },
            },
            _count: {
              select: {
                messages: {
                  where: {
                    NOT: {
                      read_receipts: {
                        some: {
                          user_id: userId,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      orderBy: {
        chat: {
          last_activity: 'desc',
        },
      },
    });
  }

  async markChatAsRead(userId: number, chatId: number) {
    const isMember = await this.prisma.chatMember.findUnique({
      where: {
        chat_id_user_id: {
          chat_id: chatId,
          user_id: userId,
        },
      },
    });

    if (!isMember) {
      throw new ForbiddenException('Access to chat denied');
    }

    const unreadMessages = await this.prisma.message.findMany({
      where: {
        chat_id: chatId,
        NOT: {
          read_receipts: {
            some: {
              user_id: userId,
            },
          },
        },
      },
      select: { id: true },
    });

    if (unreadMessages.length > 0) {
      await this.prisma.readReceipt.createMany({
        data: unreadMessages.map((msg) => ({
          message_id: msg.id,
          user_id: userId,
        })),
        skipDuplicates: true,
      });
    }

    return { markedCount: unreadMessages.length };
  }
}

/*
import { Injectable, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateChatDto } from './dto/create-chat.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { PaginationDto } from '../common/dto/pagination.dto';

@Injectable()
export class ChatService {
  constructor(private prisma: PrismaService) {}

  async createChat(userId: number, dto: CreateChatDto) {
    // Создаем чат
    const chat = await this.prisma.chat.create({
      data: {
        chat_type: dto.chatType,
        chat_name: dto.chatName,
        created_by_id: userId,
      },
    });

    // Добавляем участников
    await this.prisma.chatMember.createMany({
      data: [
        { chat_id: chat.id, user_id: userId, is_admin: true },
        ...dto.members.map((memberId) => ({
          chat_id: chat.id,
          user_id: memberId,
          is_admin: false,
        })),
      ],
    });

    return chat;
  }

  async sendMessage(userId: number, dto: SendMessageDto) {
    // Проверяем, что пользователь состоит в чате
    const membership = await this.prisma.chatMember.findUnique({
      where: {
        chat_id_user_id: {
          chat_id: dto.chatId,
          user_id: userId,
        },
      },
    });

    if (!membership) {
      throw new NotFoundException('Chat not found or access denied');
    }

    // Создаем сообщение
    const message = await this.prisma.message.create({
      data: {
        content: dto.content,
        chat_id: dto.chatId,
        sender_id: userId,
      },
    });

    // Обновляем время последней активности чата
    await this.prisma.chat.update({
      where: { id: dto.chatId },
      data: { last_activity: new Date() },
    });

    return message;
  }

  async getChatHistory(chatId: number, userId: number) {
    // Проверяем доступ к чату
    const membership = await this.prisma.chatMember.findUnique({
      where: {
        chat_id_user_id: {
          chat_id: chatId,
          user_id: userId,
        },
      },
    });

    if (!membership) {
      throw new NotFoundException('Chat not found or access denied');
    }

    return this.prisma.message.findMany({
      where: { chat_id: chatId },
      include: { sender: true, attachments: true },
      orderBy: { created_at: 'asc' },
    });
  }

  async getMessages(userId: number, chatId: number, pagination: PaginationDto) {
    // Проверка прав доступа
    const isMember = await this.prisma.chatMember.findUnique({
      where: {
        chat_id_user_id: {
          chat_id: chatId,
          user_id: userId,
        },
      },
    });

    if (!isMember) {
      throw new ForbiddenException('Access to chat denied');
    }

    return this.prisma.message.findMany({
      where: { chat_id: chatId },
      include: {
        sender: {
          select: {
            id: true,
            username: true,
            avatar_path: true,
          },
        },
        attachments: true,
        read_receipts: {
          where: { user_id: userId },
          select: { read_at: true },
        },
      },
      orderBy: { created_at: 'desc' },
      skip: (pagination.page - 1) * pagination.limit,
      take: pagination.limit,
    });
  }

  async deleteMessage(userId: number, messageId: bigint) {
    const message = await this.prisma.message.findUnique({
      where: { id: messageId },
      include: { sender: true },
    });

    if (!message) {
      throw new NotFoundException('Message not found');
    }

    if (message.sender_id !== userId) {
      throw new ForbiddenException('You can only delete your own messages');
    }

    return this.prisma.message.delete({
      where: { id: messageId },
    });
  }

  async getUserChats(userId: number) {
    return this.prisma.chatMember.findMany({
      where: { user_id: userId },
      include: {
        chat: {
          include: {
            messages: {
              orderBy: { created_at: 'desc' },
              take: 1,
              include: {
                sender: {
                  select: {
                    username: true,
                  },
                },
              },
            },
            _count: {
              select: {
                messages: {
                  where: {
                    NOT: {
                      read_receipts: {
                        some: {
                          user_id: userId,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      orderBy: {
        chat: {
          last_activity: 'desc',
        },
      },
    });
  }

  async markChatAsRead(userId: number, chatId: number) {
    // Проверка прав доступа
    const isMember = await this.prisma.chatMember.findUnique({
      where: {
        chat_id_user_id: {
          chat_id: chatId,
          user_id: userId,
        },
      },
    });

    if (!isMember) {
      throw new ForbiddenException('Access to chat denied');
    }

    // Получаем все непрочитанные сообщения
    const unreadMessages = await this.prisma.message.findMany({
      where: {
        chat_id: chatId,
        NOT: {
          read_receipts: {
            some: {
              user_id: userId,
            },
          },
        },
      },
      select: { id: true },
    });

    // Создаем записи о прочтении
    if (unreadMessages.length > 0) {
      await this.prisma.readReceipt.createMany({
        data: unreadMessages.map((msg) => ({
          message_id: msg.id,
          user_id: userId,
        })),
        skipDuplicates: true,
      });
    }

    return { markedCount: unreadMessages.length };
  }
}*/