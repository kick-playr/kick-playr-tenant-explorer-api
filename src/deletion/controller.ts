import {
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { PlatformGuard, type PlatformRequest } from '../auth.js';
import { DeletionService } from './service.js';
@ApiTags('Platform tenant deletion')
@ApiBearerAuth()
@UseGuards(PlatformGuard)
@Controller('api/platform/tenants/:environment/:id/deletion')
export class DeletionController {
  constructor(
    @Inject(DeletionService) private readonly service: DeletionService,
  ) {}
  @Get()
  @ApiOperation({
    summary: 'Read deletion impact, recovery and verified cleanup inventory',
  })
  status(
    @Param('environment') environment: string,
    @Param('id') tenantId: string,
  ) {
    return this.service.status({ environment, tenantId });
  }
  @Post()
  @ApiOperation({
    summary: 'Block tenant access with three calendar months recovery',
  })
  remove(
    @Param('environment') environment: string,
    @Param('id') tenantId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.remove(
      { environment, tenantId },
      body,
      req.platformSubject,
    );
  }
  @Post('recover')
  @ApiOperation({
    summary: 'Recover retained tenant to disabled, with fresh grants required',
  })
  recover(
    @Param('environment') environment: string,
    @Param('id') tenantId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.recover(
      { environment, tenantId },
      body,
      req.platformSubject,
    );
  }
  @Post('purge')
  @ApiOperation({
    summary:
      'Permanently delete verified database targets after manual cleanup confirmation',
  })
  purge(
    @Param('environment') environment: string,
    @Param('id') tenantId: string,
    @Body() body: unknown,
    @Req() req: PlatformRequest,
  ) {
    return this.service.purge(
      { environment, tenantId },
      body,
      req.platformSubject,
    );
  }
}
