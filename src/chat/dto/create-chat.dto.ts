import { IsArray, IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ChatType } from '@prisma/client';

export class CreateChatDto {
  @IsEnum(ChatType)
  chatType: ChatType;

  @IsString()
  @IsOptional()
  chatName?: string;

  @IsArray()
  @IsNotEmpty()
  members: number[];
}