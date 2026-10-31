import type {
  Aggregate,
  AuditEvent,
  ListQuery,
  TenantSummary,
} from '../src/contracts.js';
import type { Repository, Transaction } from '../src/repository.js';

// Transactional storage double. No network or Mongo process is started by tests.
export class MemoryRepository implements Repository {
  async clubDefinitions(issuer: string, subject: string) {
    return structuredClone(
      [...this.rows.values()]
        .filter((a) =>
          a.authority?.users.some(
            (g) => g.issuer === issuer && g.subject === subject,
          ),
        )
        .map((a) => a.definition),
    );
  }
  rows = new Map<string, Aggregate>();
  events: AuditEvent[] = [];
  private queue = Promise.resolve();
  async read(environment: string, id: string) {
    return structuredClone(this.rows.get(`${environment}/${id}`) ?? null);
  }
  async list(query: ListQuery) {
    const all = [...this.rows.values()]
      .map((x) => x.definition)
      .filter(
        (x) =>
          (!query.environment || x.environment === query.environment) &&
          (!query.status || x.status === query.status) &&
          (!query.search ||
            [x.id, x.public.name, x.hostname, ...x.aliases]
              .join(' ')
              .toLowerCase()
              .includes(query.search.toLowerCase())),
      )
      .sort(
        (a, b) =>
          a.public.name.localeCompare(b.public.name) ||
          a.id.localeCompare(b.id),
      );
    const start = (query.page - 1) * query.pageSize;
    return {
      items: structuredClone(
        all.slice(start, start + query.pageSize),
      ) as TenantSummary[],
      total: all.length,
      page: query.page,
      pageSize: query.pageSize,
    };
  }
  async audit(environment: string, tenantId: string) {
    return structuredClone(
      this.events
        .filter((e) => e.environment === environment && e.tenantId === tenantId)
        .slice(-100)
        .reverse(),
    );
  }
  async transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    const previous = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    const rows = structuredClone(this.rows),
      events = structuredClone(this.events);
    try {
      const result = await work({
        read: async (environment, id) =>
          structuredClone(rows.get(`${environment}/${id}`) ?? null),
        save: async (aggregate, expectedRevision) => {
          const key = `${aggregate.definition.environment}/${aggregate.definition.id}`;
          const existing = rows.get(key);
          if (
            (existing?.definition.configRevision ?? null) !== expectedRevision
          )
            throw new Error('Tenant revision changed; reload');
          const hosts = [
            aggregate.definition.hostname,
            ...aggregate.definition.aliases,
          ];
          for (const [other, row] of rows)
            if (
              other !== key &&
              row.definition.environment === aggregate.definition.environment &&
              [row.definition.hostname, ...row.definition.aliases].some((h) =>
                hosts.includes(h),
              )
            )
              throw new Error('Tenant domain already assigned');
          rows.set(key, structuredClone(aggregate));
        },
        appendAudit: async (event) => {
          events.push(structuredClone(event));
        },
      });
      this.rows = rows;
      this.events = events;
      return result;
    } finally {
      release();
    }
  }
}
