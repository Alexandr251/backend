import {
  Controller,
  Post,
  Body,
  UploadedFiles,
  UseInterceptors,
  UseGuards,
  Req,
  Get,
  Param,
  Delete,
  Query,
  Res,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import { ChatService } from './chat.service';
import { CreateChatDto } from './dto/create-chat.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuthRequest } from '../auth/types';
import { Response } from 'express';
import { diskStorage } from 'multer';
import { extname, join } from 'path';
import { existsSync } from 'fs';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { FileSizeValidationPipe } from '../common/decorators/pipes/file-size.pipe';
import { FileTypeValidationPipe } from '../common/decorators/pipes/file-type.pipe';
import { PaginationDto } from '../common/dto/pagination.dto';

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'application/pdf',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

@ApiTags('Chat')
@ApiBearerAuth()
@Controller('chat')
@UseGuards(JwtAuthGuard)
export class ChatController {
  private readonly logger = new Logger(ChatController.name);

  constructor(private chatService: ChatService) {}

  @Post()
  @ApiOperation({ summary: 'Create new chat' })
  @ApiResponse({ status: 201, description: 'Chat created successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createChat(@Req() req: AuthRequest, @Body() dto: CreateChatDto) {
    try {
      const chat = await this.chatService.createChat(req.user.sub, dto);
      return {
        status: 'success',
        data: chat,
      };
    } catch (error) {
      this.logger.error(`Failed to create chat: ${error.message}`);
      throw error;
    }
  }

  @Post('message')
  @ApiOperation({ summary: 'Send message with attachments' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Message data with attachments',
    type: SendMessageDto,
  })
  @UseInterceptors(
    FilesInterceptor('attachments', 5, {
      storage: diskStorage({
        destination: './uploads',
        filename: (req, file, cb) => {
          const randomName = Array(32)
            .fill(null)
            .map(() => Math.round(Math.random() * 16).toString(16))
            .join('');
          return cb(null, `${randomName}${extname(file.originalname)}`);
        },
      }),
      fileFilter: (req, file, cb) => {
        if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
          cb(null, true);
        } else {
          cb(new Error('Invalid file type'), false);
        }
      },
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
      },
    }),
  )
  async sendMessage(
    @Req() req: AuthRequest,
    @Body() dto: SendMessageDto,
    @UploadedFiles(
      new FileSizeValidationPipe(10 * 1024 * 1024), // 10MB
      new FileTypeValidationPipe(ALLOWED_MIME_TYPES),
    )
    attachments: Express.Multer.File[],
  ) {
    try {
      const messageDto = {
        ...dto,
        attachments: attachments?.map((file) => ({
          path: file.path,
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
        })),
      };

      const message = await this.chatService.sendMessage(
        req.user.sub,
        messageDto,
      );

      return {
        status: 'success',
        data: message,
      };
    } catch (error) {
      this.logger.error(`Failed to send message: ${error.message}`);
      throw error;
    }
  }

  @Get('messages/:chatId')
  @ApiOperation({ summary: 'Get chat messages' })
  @ApiResponse({ status: 200, description: 'Messages retrieved successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async getMessages(
    @Req() req: AuthRequest,
    @Param('chatId') chatId: string,
    @Query() pagination: PaginationDto,
  ) {
    try {
      const messages = await this.chatService.getMessages(
        req.user.sub,
        parseInt(chatId),
        pagination,
      );
      return {
        status: 'success',
        data: messages,
      };
    } catch (error) {
      this.logger.error(`Failed to get messages: ${error.message}`);
      throw error;
    }
  }

  @Get('download/:filename')
  @ApiOperation({ summary: 'Download attachment' })
  async downloadFile(
    @Param('filename') filename: string,
    @Res() res: Response,
  ) {
    try {
      const filePath = join(process.cwd(), 'uploads', filename);

      if (!existsSync(filePath)) {
        return res.status(HttpStatus.NOT_FOUND).json({
          status: 'error',
          message: 'File not found',
        });
      }

      res.download(filePath);
    } catch (error) {
      this.logger.error(`Failed to download file: ${error.message}`);
      throw error;
    }
  }

  @Delete('message/:messageId')
  @ApiOperation({ summary: 'Delete message' })
  @ApiResponse({ status: 200, description: 'Message deleted successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async deleteMessage(
    @Req() req: AuthRequest,
    @Param('messageId') messageId: string,
  ) {
    try {
      await this.chatService.deleteMessage(
        req.user.sub,
        BigInt(messageId),
      );
      return {
        status: 'success',
        message: 'Message deleted',
      };
    } catch (error) {
      this.logger.error(`Failed to delete message: ${error.message}`);
      throw error;
    }
  }

  @Get('chats')
  @ApiOperation({ summary: 'Get user chats' })
  @ApiResponse({ status: 200, description: 'Chats retrieved successfully' })
  async getUserChats(@Req() req: AuthRequest) {
    try {
      const chats = await this.chatService.getUserChats(req.user.sub);
      return {
        status: 'success',
        data: chats,
      };
    } catch (error) {
      this.logger.error(`Failed to get user chats: ${error.message}`);
      throw error;
    }
  }

  @Post('chats/:chatId/read')
  @ApiOperation({ summary: 'Mark chat messages as read' })
  async markAsRead(
    @Req() req: AuthRequest,
    @Param('chatId') chatId: string,
  ) {
    try {
      await this.chatService.markChatAsRead(req.user.sub, parseInt(chatId));
      return {
        status: 'success',
        message: 'Messages marked as read',
      };
    } catch (error) {
      this.logger.error(`Failed to mark messages as read: ${error.message}`);
      throw error;
    }
  }
}





















































/*
import {
  Controller,
  Post,
  Body,
  UploadedFiles,
  UseInterceptors,
  UseGuards,
  Req,
  Get,
  Param,
  Delete,
  Query,
  Res,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import { ChatService } from './chat.service';
import { CreateChatDto } from './dto/create-chat.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Request, Response } from 'express';
import { diskStorage } from 'multer';
import { extname, join } from 'path';
import { existsSync } from 'fs';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { FileSizeValidationPipe } from '../common/decorators/pipes/file-size.pipe';
import { FileTypeValidationPipe } from '../common/decorators/pipes/file-type.pipe';
import { PaginationDto } from '../common/dto/pagination.dto';

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'application/pdf',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

@ApiTags('Chat')
@ApiBearerAuth()
@Controller('chat')
@UseGuards(JwtAuthGuard)
export class ChatController {
  private readonly logger = new Logger(ChatController.name);

  constructor(private chatService: ChatService) {}

  @Post()
  @ApiOperation({ summary: 'Create new chat' })
  @ApiResponse({ status: 201, description: 'Chat created successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createChat(@Req() req: Request, @Body() dto: CreateChatDto) {
    try {
      const chat = await this.chatService.createChat(req.user.userId, dto);
      return {
        status: 'success',
        data: chat,
      };
    } catch (error) {
      this.logger.error(`Failed to create chat: ${error.message}`);
      throw error;
    }
  }

  @Post('message')
  @ApiOperation({ summary: 'Send message with attachments' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Message data with attachments',
    type: SendMessageDto,
  })
  @UseInterceptors(
    FilesInterceptor('attachments', 5, {
      storage: diskStorage({
        destination: './uploads',
        filename: (req, file, cb) => {
          const randomName = Array(32)
            .fill(null)
            .map(() => Math.round(Math.random() * 16).toString(16))
            .join('');
          return cb(null, `${randomName}${extname(file.originalname)}`);
        },
      }),
      fileFilter: (req, file, cb) => {
        if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
          cb(null, true);
        } else {
          cb(new Error('Invalid file type'), false);
        }
      },
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
      },
    }),
  )
  async sendMessage(
    @Req() req: Request,
    @Body() dto: SendMessageDto,
    @UploadedFiles(
      new FileSizeValidationPipe(10 * 1024 * 1024), // 10MB
      new FileTypeValidationPipe(ALLOWED_MIME_TYPES),
    )
    attachments: Express.Multer.File[],
  ) {
    try {
      const messageDto = {
        ...dto,
        attachments: attachments?.map((file) => ({
          path: file.path,
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
        })),
      };

      const message = await this.chatService.sendMessage(
        req.user.userId,
        messageDto,
      );

      return {
        status: 'success',
        data: message,
      };
    } catch (error) {
      this.logger.error(`Failed to send message: ${error.message}`);
      throw error;
    }
  }

  @Get('messages/:chatId')
  @ApiOperation({ summary: 'Get chat messages' })
  @ApiResponse({ status: 200, description: 'Messages retrieved successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async getMessages(
    @Req() req: Request,
    @Param('chatId') chatId: number,
    @Query() pagination: PaginationDto,
  ) {
    try {
      const messages = await this.chatService.getMessages(
        req.user.userId,
        +chatId,
        pagination,
      );
      return {
        status: 'success',
        data: messages,
      };
    } catch (error) {
      this.logger.error(`Failed to get messages: ${error.message}`);
      throw error;
    }
  }

  @Get('download/:filename')
  @ApiOperation({ summary: 'Download attachment' })
  async downloadFile(
    @Param('filename') filename: string,
    @Res() res: Response,
  ) {
    try {
      const filePath = join(process.cwd(), 'uploads', filename);

      if (!existsSync(filePath)) {
        return res.status(HttpStatus.NOT_FOUND).json({
          status: 'error',
          message: 'File not found',
        });
      }

      res.download(filePath);
    } catch (error) {
      this.logger.error(`Failed to download file: ${error.message}`);
      throw error;
    }
  }

  @Delete('message/:messageId')
  @ApiOperation({ summary: 'Delete message' })
  @ApiResponse({ status: 200, description: 'Message deleted successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async deleteMessage(
    @Req() req: Request,
    @Param('messageId') messageId: string,
  ) {
    try {
      await this.chatService.deleteMessage(
        req.user.userId,
        BigInt(messageId),
      );
      return {
        status: 'success',
        message: 'Message deleted',
      };
    } catch (error) {
      this.logger.error(`Failed to delete message: ${error.message}`);
      throw error;
    }
  }

  @Get('chats')
  @ApiOperation({ summary: 'Get user chats' })
  @ApiResponse({ status: 200, description: 'Chats retrieved successfully' })
  async getUserChats(@Req() req: Request) {
    try {
      const chats = await this.chatService.getUserChats(req.user.userId);
      return {
        status: 'success',
        data: chats,
      };
    } catch (error) {
      this.logger.error(`Failed to get user chats: ${error.message}`);
      throw error;
    }
  }

  @Post('chats/:chatId/read')
  @ApiOperation({ summary: 'Mark chat messages as read' })
  async markAsRead(
    @Req() req: Request,
    @Param('chatId') chatId: number,
  ) {
    try {
      await this.chatService.markChatAsRead(req.user.userId, +chatId);
      return {
        status: 'success',
        message: 'Messages marked as read',
      };
    } catch (error) {
      this.logger.error(`Failed to mark messages as read: ${error.message}`);
      throw error;
    }
  }
}
*/





/*
import {
  Controller,
  Post,
  Body,
  UploadedFiles,
  UseInterceptors,
  UseGuards,
  Req,
  Get,
  Param,
  Delete,
  Query,
  Res,
  HttpStatus, Logger,
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import { ChatService } from './chat.service';
import { CreateChatDto } from './dto/create-chat.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Request, Response } from 'express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { FileSizeValidationPipe } from '../common/decorators/pipes/file-size.pipe';
import { FileTypeValidationPipe } from '../common/decorators/pipes/file-type.pipe';
import { PaginationDto } from '../common/dto/pagination.dto';
import { join } from '@prisma/client/runtime/edge';

// Допустимые MIME-типы файлов
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'application/pdf',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

@ApiTags('Chat')
@ApiBearerAuth()
@Controller('chat')
@UseGuards(JwtAuthGuard)
export class ChatController {
  private readonly logger = new Logger(ChatController.name);

  constructor(private chatService: ChatService) {}

  @Post()
  @ApiOperation({ summary: 'Create new chat' })
  @ApiResponse({ status: 201, description: 'Chat created successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createChat(@Req() req: Request, @Body() dto: CreateChatDto) {
    try {
      const chat = await this.chatService.createChat(req.user.userId, dto);
      return {
        status: 'success',
        data: chat,
      };
    } catch (error) {
      this.logger.error(`Failed to create chat: ${error.message}`);
      throw error;
    }
  }

  @Post('message')
  @ApiOperation({ summary: 'Send message with attachments' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Message data with attachments',
    type: SendMessageDto,
  })
  @UseInterceptors(
    FilesInterceptor('attachments', 5, {
      storage: diskStorage({
        destination: './uploads',
        filename: (req, file, cb) => {
          const randomName = Array(32)
            .fill(null)
            .map(() => Math.round(Math.random() * 16).toString(16))
            .join('');
          return cb(null, `${randomName}${extname(file.originalname)}`);
        },
      }),
      fileFilter: (req, file, cb) => {
        if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
          cb(null, true);
        } else {
          cb(new Error('Invalid file type'), false);
        }
      },
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
      },
    }),
  )
  async sendMessage(
    @Req() req: Request,
    @Body() dto: SendMessageDto,
    @UploadedFiles(
      new FileSizeValidationPipe(10 * 1024 * 1024), // 10MB
      new FileTypeValidationPipe(ALLOWED_MIME_TYPES),
    )
    attachments: Express.Multer.File[],
  ) {
    try {
      const messageDto = {
        ...dto,
        attachments: attachments?.map((file) => ({
          path: file.path,
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
        })),
      };

      const message = await this.chatService.sendMessage(
        req.user.userId,
        messageDto,
      );

      return {
        status: 'success',
        data: message,
      };
    } catch (error) {
      this.logger.error(`Failed to send message: ${error.message}`);
      throw error;
    }
  }

  @Get('messages/:chatId')
  @ApiOperation({ summary: 'Get chat messages' })
  @ApiResponse({ status: 200, description: 'Messages retrieved successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async getMessages(
    @Req() req: Request,
    @Param('chatId') chatId: number,
    @Query() pagination: PaginationDto,
  ) {
    try {
      const messages = await this.chatService.getMessages(
        req.user.userId,
        +chatId,
        pagination,
      );
      return {
        status: 'success',
        data: messages,
      };
    } catch (error) {
      this.logger.error(`Failed to get messages: ${error.message}`);
      throw error;
    }
  }

  @Get('download/:filename')
  @ApiOperation({ summary: 'Download attachment' })
  async downloadFile(
    @Param('filename') filename: string,
    @Res() res: Response,
  ) {
    try {
      const filePath = join(process.cwd(), 'uploads', filename);
      const fileExists = existsSync(filePath);

      if (!fileExists) {
        return res.status(HttpStatus.NOT_FOUND).json({
          status: 'error',
          message: 'File not found',
        });
      }

      res.download(filePath);
    } catch (error) {
      this.logger.error(`Failed to download file: ${error.message}`);
      throw error;
    }
  }

  @Delete('message/:messageId')
  @ApiOperation({ summary: 'Delete message' })
  @ApiResponse({ status: 200, description: 'Message deleted successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async deleteMessage(
    @Req() req: Request,
    @Param('messageId') messageId: string,
  ) {
    try {
      await this.chatService.deleteMessage(
        req.user.userId,
        BigInt(messageId),
      );
      return {
        status: 'success',
        message: 'Message deleted',
      };
    } catch (error) {
      this.logger.error(`Failed to delete message: ${error.message}`);
      throw error;
    }
  }

  @Get('chats')
  @ApiOperation({ summary: 'Get user chats' })
  @ApiResponse({ status: 200, description: 'Chats retrieved successfully' })
  async getUserChats(@Req() req: Request) {
    try {
      const chats = await this.chatService.getUserChats(req.user.userId);
      return {
        status: 'success',
        data: chats,
      };
    } catch (error) {
      this.logger.error(`Failed to get user chats: ${error.message}`);
      throw error;
    }
  }

  @Post('chats/:chatId/read')
  @ApiOperation({ summary: 'Mark chat messages as read' })
  async markAsRead(
    @Req() req: Request,
    @Param('chatId') chatId: number,
  ) {
    try {
      await this.chatService.markChatAsRead(req.user.userId, +chatId);
      return {
        status: 'success',
        message: 'Messages marked as read',
      };
    } catch (error) {
      this.logger.error(`Failed to mark messages as read: ${error.message}`);
      throw error;
    }
  }
}*/