import { IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';

export class SendMessageDto {
  @IsNumber()
  chatId: number;

  @IsString()
  @IsNotEmpty()
  content: string;

  @IsOptional()
  attachments?: any[];
}