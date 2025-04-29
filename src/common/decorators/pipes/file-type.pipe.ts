import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';

@Injectable()
export class FileTypeValidationPipe implements PipeTransform {
  constructor(private readonly allowedTypes: string[]) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (value) {
      const files = Array.isArray(value) ? value : [value];
      for (const file of files) {
        if (!this.allowedTypes.includes(file.mimetype)) {
          throw new BadRequestException(
            `File type ${file.mimetype} is not allowed`,
          );
        }
      }
    }
    return value;
  }
}