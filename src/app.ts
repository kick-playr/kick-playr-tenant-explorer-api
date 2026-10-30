import 'reflect-metadata';
import {
  Catch,
  Controller,
  Get,
  HttpException,
  Module,
  type ArgumentsHost,
  type ExceptionFilter,
  type INestApplication,
} from '@nestjs/common';
import { APP_GUARD, NestFactory, Reflector } from '@nestjs/core';
import {
  getOptionsToken,
  getStorageToken,
  ThrottlerGuard,
  ThrottlerModule,
  type ThrottlerModuleOptions,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { json } from 'express';
import type { Response } from 'express';
import helmet from 'helmet';
import {
  AUTH_OPTIONS,
  PlatformGuard,
  type PlatformAuthOptions,
} from './auth.js';
import type { Repository } from './repository.js';
import { TenantController } from './tenant.controller.js';
import { TenantService } from './tenant.service.js';
import { CredentialVault } from './vault.js';
import { KeyFileRegistry } from './key-files.js';

@Catch()
class SafeExceptionFilter implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse<Response>();
    // Nest plugins can use a separate CJS HttpException under the tsx loader.
    // Recognize its public contract without exposing arbitrary error messages.
    const exception =
      error instanceof HttpException ||
      (error instanceof Error &&
        'getStatus' in error &&
        typeof error.getStatus === 'function' &&
        'getResponse' in error &&
        typeof error.getResponse === 'function')
        ? (error as HttpException)
        : null;
    const tooLarge = (error as { type?: string })?.type === 'entity.too.large';
    const reportedStatus = exception?.getStatus();
    const status =
      Number.isInteger(reportedStatus) &&
      reportedStatus! >= 400 &&
      reportedStatus! <= 599
        ? reportedStatus!
        : tooLarge
          ? 413
          : 500;
    const payload = exception?.getResponse() ?? null;
    const message =
      status >= 500
        ? 'An unexpected error occurred'
        : tooLarge
          ? 'Request exceeds 64KB'
          : typeof payload === 'object' &&
              payload !== null &&
              'message' in payload
            ? payload.message
            : typeof payload === 'string'
              ? payload
              : 'Request rejected';
    response.status(status).json({ statusCode: status, message });
  }
}
@Controller()
class HealthController {
  @Get('healthcheck') health() {
    return { status: 'ok', service: 'tenant-explorer-api' };
  }
}

export interface AppOptions {
  repository: Repository;
  vault: CredentialVault;
  auth: PlatformAuthOptions;
  logger?: false;
  keyFiles?: KeyFileRegistry;
}
export async function createApp(
  options: AppOptions,
): Promise<INestApplication> {
  @Module({
    imports: [ThrottlerModule.forRoot([{ ttl: 60000, limit: 120 }])],
    controllers: [TenantController, HealthController],
    providers: [
      { provide: AUTH_OPTIONS, useValue: options.auth },
      PlatformGuard,
      { provide: 'REPOSITORY', useValue: options.repository },
      {
        provide: TenantService,
        useFactory: () =>
          new TenantService(
            options.repository,
            options.vault,
            options.keyFiles,
          ),
      },
      {
        provide: APP_GUARD,
        inject: [getOptionsToken(), getStorageToken(), Reflector],
        // tsx may load the CJS throttler's Reflector separately from ESM Nest.
        // Use this module's Nest token instead of the guard's emitted metadata.
        useFactory: (
          options: ThrottlerModuleOptions,
          storage: ThrottlerStorage,
          reflector: Reflector,
        ) => new ThrottlerGuard(options, storage, reflector),
      },
    ],
  })
  class ExplorerModule {}
  const app = await NestFactory.create(ExplorerModule, {
    bodyParser: false,
    logger: options.logger,
  });
  app.use(helmet());
  app.use((_req: unknown, res: Response, next: () => void) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(json({ limit: '64kb' }));
  app.useGlobalFilters(new SafeExceptionFilter());
  const document = SwaggerModule.createDocument(
    app,
    new DocumentBuilder()
      .setTitle('Kick Playr Tenant Explorer API')
      .setDescription(
        'Platform administration. Requires an allowlisted Clerk session. Explorer integration records do not provision external providers.',
      )
      .setVersion('0.1.0')
      .addBearerAuth()
      .build(),
  );
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: { persistAuthorization: false },
  });
  app.enableShutdownHooks();
  return app;
}
