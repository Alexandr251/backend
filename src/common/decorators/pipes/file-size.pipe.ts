import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';

@Injectable()
export class FileSizeValidationPipe implements PipeTransform {
  constructor(private readonly maxSize: number) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (value) {
      const files = Array.isArray(value) ? value : [value];
      for (const file of files) {
        if (file.size > this.maxSize) {
          throw new BadRequestException(
            `File ${file.originalname} is too large. Maximum size is ${this.maxSize / 1024 / 1024}MB`,
          );
        }
      }
    }
    return value;
  }
}