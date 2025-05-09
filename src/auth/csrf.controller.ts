import { Controller, Get, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';

@Controller('csrf')
export class CsrfController {
  @Get()
  getCsrfToken(@Req() req: Request, @Res() res: Response) {
    return res.json({ csrfToken: req.csrfToken() });
  }
}
