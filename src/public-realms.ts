import { BadRequestException, NotFoundException } from '@nestjs/common';
import {
  validRealmHost,
  type ExplorerDatabaseConfiguration,
} from './database-config.js';
export class PublicRealmDirectory {
  private readonly hosts: ExplorerDatabaseConfiguration['frontendHosts'];
  private readonly platform: Set<string>;
  constructor(
    config: Pick<
      ExplorerDatabaseConfiguration,
      'frontendHosts' | 'platformHosts'
    > = { frontendHosts: {}, platformHosts: [] },
    private readonly configuration?: () => Pick<ExplorerDatabaseConfiguration, 'frontendHosts' | 'platformHosts'>,
  ) {
    this.hosts = structuredClone(config.frontendHosts);
    this.platform = new Set(config.platformHosts);
  }
  resolve(query: Record<string, unknown>): {host: string; club: boolean; publishableKey?: string; secretVariable?: string} {
    if (this.configuration) {
      return new PublicRealmDirectory(this.configuration()).resolve(query);
    }
    if (
      Object.keys(query).length !== 1 ||
      !Object.hasOwn(query, 'host') ||
      !validRealmHost(query.host)
    )
      throw new BadRequestException('Invalid realm host');
    const host = query.host;
    if (Object.hasOwn(this.hosts, host)) {
      const realm = this.hosts[host]!;
      return {
        host,
        publishableKey: realm.publishableKey,
        secretVariable: realm.secretVariable,
        club: true as const,
      };
    }
    if (this.platform.has(host)) return { host, club: false as const };
    throw new NotFoundException('Realm host is unavailable');
  }
}
