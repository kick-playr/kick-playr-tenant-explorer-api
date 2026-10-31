import 'reflect-metadata';
import {
  Catch,
  Controller,
  Get,
  Inject,
  Query,
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
  ExplorerSessionGuard,
  type PlatformAuthOptions,
} from './auth.js';
import type { Repository } from './repository.js';
import { TenantController } from './tenant.controller.js';
import { TenantService } from './tenant.service.js';
import { CredentialVault } from './vault.js';
import { KeyFileRegistry } from './key-files.js';
import { ClubAccess } from './club-access.js';
import { ClubRuntime } from './club-runtime.js';
import { ClubController, ExplorerAccessController } from './club.controller.js';
import { PublicRealmDirectory } from './public-realms.js';

import { InvitationService } from './invitations/service.js';
import { OnboardingService } from './onboarding/service.js';
import {
  OnboardingController,
  ProvisioningController,
} from './onboarding/controller.js';
import {
  PlatformInvitationsController,
  ClubInvitationsController,
  AcceptanceController,
  InvitationPlatformGuard,
} from './invitations/controller.js';
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
@Controller('public')
class PublicRealmController {
  constructor(
    @Inject(PublicRealmDirectory) private readonly realms: PublicRealmDirectory,
  ) {}
  @Get('realm')
  realm(@Query() query: Record<string, unknown>) {
    return this.realms.resolve(query);
  }
}

export interface AppOptions {
  repository: Repository;
  vault: CredentialVault;
  auth: PlatformAuthOptions;
  logger?: false;
  keyFiles?: KeyFileRegistry;
  clubRuntime?: ClubRuntime;
  publicRealms?: PublicRealmDirectory;
  invitations?: InvitationService;
  onboarding?: OnboardingService;
}
export async function createApp(
  options: AppOptions,
): Promise<INestApplication> {
  @Module({
    imports: [ThrottlerModule.forRoot([{ ttl: 60000, limit: 120 }])],
    controllers: [
      TenantController,
      HealthController,
      ClubController,
      ExplorerAccessController,
      PublicRealmController,
      PlatformInvitationsController,
      ClubInvitationsController,
      AcceptanceController,
      OnboardingController,
      ProvisioningController,
    ],
    providers: [
      { provide: AUTH_OPTIONS, useValue: options.auth },
      {
        provide: PublicRealmDirectory,
        useValue: options.publicRealms ?? new PublicRealmDirectory(),
      },
      PlatformGuard,
      InvitationPlatformGuard,
      {
        provide: OnboardingService,
        useValue:
          options.onboarding ??
          new Proxy(
            {},
            {
              get: (_target, key) =>
                [
                  'status',
                  'run',
                  'complete',
                  'confirm',
                  'reviews',
                  'reviewContact',
                  'provisioning',
                  'saveProvisioning',
                  'verifyProvisioning',
                ].includes(String(key))
                  ? () => {
                      throw new HttpException('Setup unavailable', 503);
                    }
                  : undefined,
            },
          ),
      },
      {
        provide: InvitationService,
        useValue:
          options.invitations ??
          new Proxy(
            {},
            {
              get: (_target, key) =>
                [
                  'create',
                  'list',
                  'resend',
                  'revoke',
                  'revokeAccess',
                  'deliver',
                  'preview',
                  'accept',
                  'status',
                ].includes(String(key))
                  ? () => {
                      throw new HttpException('Invitations unavailable', 503);
                    }
                  : undefined,
            },
          ),
      },
      ExplorerSessionGuard,
      {
        provide: ClubAccess,
        useFactory: () => new ClubAccess(options.repository),
      },
      {
        provide: ClubRuntime,
        useValue: options.clubRuntime ?? new ClubRuntime(),
      },
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
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });
  app.use(json({ limit: '64kb' }));
  app.useGlobalFilters(new SafeExceptionFilter());
  const document = SwaggerModule.createDocument(
    app,
    new DocumentBuilder()
      .setTitle('Kick Playr Tenant Explorer API')
      .setDescription(
        'Platform routes require an allowlisted platform Clerk session. Club routes require exact active tenant administrator grants and use the existing authenticated club runtime and encrypted storage.',
      )
      .setVersion('0.1.1')
      .addBearerAuth()
      .build(),
  );
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: { persistAuthorization: false },
  });
  app.enableShutdownHooks();
  return app;
}
