import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MongoClient, type Document } from 'mongodb';
import { MongoRepository } from '../src/repository.js';
import { listSchema, parse, type Aggregate } from '../src/contracts.js';
import { MemoryRepository } from './memory-repository.js';
const definition = (
  id: string,
  status = 'disabled',
  environment = 'development',
): Document => ({
  id,
  environment,
  status,
  configRevision: 1,
  hostname: `${id}.example.invalid`,
  aliases: [],
  public: { name: `Club ${id}`, locale: 'de-CH' },
  secretReferences: { mongoUri: 'ref:mongo', key: 'ref:key' },
});
const records = [
  definition('a-active', 'active'),
  definition('b-recovered'),
  { ...definition('c-retained'), deletionId: 'retained-operation' },
  { ...definition('d-purged'), deletionId: 'purged-operation' },
  { ...definition('e-empty-marker'), deletionId: '' },
  { ...definition('f-null-marker'), deletionId: null },
  definition('g-production', 'active', 'production'),
  {
    ...definition('h-production-deleted', 'disabled', 'production'),
    deletionId: 'production-operation',
  },
];
function matches(row: Document, filter: Document): boolean {
  return Object.entries(filter).every(([field, value]) => {
    if (field === '$or')
      return value.some((part: Document) => matches(row, part));
    const actual = field.split('.').reduce((v: any, k) => v?.[k], row);
    if (value && typeof value === 'object') {
      if ('$exists' in value)
        return Object.hasOwn(row, field) === value.$exists;
      if ('$regex' in value)
        return new RegExp(value.$regex, value.$options).test(
          Array.isArray(actual) ? actual.join(' ') : String(actual),
        );
    }
    return actual === value;
  });
}
function native() {
  const filters: { find: Document[]; count: Document[] } = {
    find: [],
    count: [],
  };
  const client = {
    db: () => ({
      collection: (name: string) => {
        assert.equal(name, 'tenantDefinitions');
        return {
          find: (filter: Document) => {
            filters.find.push(structuredClone(filter));
            let skip = 0,
              limit = 100;
            const cursor = {
              sort: () => cursor,
              skip: (n: number) => {
                skip = n;
                return cursor;
              },
              limit: (n: number) => {
                limit = n;
                return cursor;
              },
              toArray: async () =>
                records
                  .filter((r) => matches(r, filter))
                  .sort((a, b) => a.public.name.localeCompare(b.public.name))
                  .slice(skip, skip + limit),
            };
            return cursor;
          },
          countDocuments: async (filter: Document) => {
            filters.count.push(structuredClone(filter));
            return records.filter((r) => matches(r, filter)).length;
          },
        };
      },
    }),
  } as unknown as MongoClient;
  return { repository: new MongoRepository(client, 'control'), filters };
}
function memory() {
  const repository = new MemoryRepository();
  for (const row of records)
    repository.rows.set(`${row.environment}/${row.id}`, {
      definition: structuredClone(row),
      authority: null,
      metadata: { configuration: {}, credentials: [], integrations: [] },
    } as unknown as Aggregate);
  return repository;
}
for (const adapter of ['native', 'memory'] as const)
  test(`${adapter} tenant lists exclude retained/purged markers by property presence and paginate after filtering`, async () => {
    const f =
      adapter === 'native' ? native() : { repository: memory(), filters: null };
    const query = (input: Record<string, unknown> = {}) =>
      parse(listSchema, { environment: 'development', ...input });
    const first = await f.repository.list(query({ pageSize: 1 }));
    assert.deepEqual(
      first.items.map((x) => x.id),
      ['a-active'],
    );
    assert.equal(first.total, 2);
    const second = await f.repository.list(query({ page: 2, pageSize: 1 }));
    assert.deepEqual(
      second.items.map((x) => x.id),
      ['b-recovered'],
    );
    assert.equal(second.total, 2);
    const third = await f.repository.list(query({ page: 3, pageSize: 1 }));
    assert.equal(third.items.length, 0);
    assert.equal(third.total, 2);
    const disabled = await f.repository.list(
      query({ status: 'disabled', search: 'Club' }),
    );
    assert.deepEqual(
      disabled.items.map((x) => x.id),
      ['b-recovered'],
    );
    assert.equal(disabled.total, 1);
    assert.equal(
      (await f.repository.list(query({ search: 'retained' }))).total,
      0,
    );
    const production = await f.repository.list(
      query({ environment: 'production' }),
    );
    assert.deepEqual(
      production.items.map((x) => x.id),
      ['g-production'],
    );
    assert.equal(production.total, 1);
    const deleted = await f.repository.list(
      query({ deletion: 'only', page: 2, pageSize: 2 }),
    );
    assert.deepEqual(
      deleted.items.map((x) => x.id),
      ['e-empty-marker', 'f-null-marker'],
    );
    assert.equal(deleted.total, 4);
    const retained = await f.repository.list(
      query({ deletion: 'only', search: 'retained', status: 'disabled' }),
    );
    assert.deepEqual(
      retained.items.map((x) => x.id),
      ['c-retained'],
    );
    assert.equal(retained.total, 1);
    if (f.filters) {
      assert.equal(f.filters.find.length, f.filters.count.length);
      f.filters.find.forEach((filter, i) => {
        assert.deepEqual(filter, f.filters.count[i]);
        assert.deepEqual(filter.deletionId, { $exists: i >= 6 });
      });
    }
  });
