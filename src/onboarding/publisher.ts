import { ConflictException, ForbiddenException } from '@nestjs/common';
import type { ClientSession, Document, MongoClient } from 'mongodb';
import type { InvitationState } from '../invitations/types.js';
import { tenantPermissionCatalog } from '../tenant-permissions.js';
import type { RuntimePublication } from './types.js';
/** Called only inside the invitation store's snapshot/majority transaction. No provider I/O. */
export async function publishManagerRuntime(
  client: MongoClient,
  database: string,
  session: ClientSession,
  definition: Document,
  authority: Document,
  state: InvitationState,
  input: RuntimePublication,
) {
  const authorized=()=>{if(input.expiresAt!==undefined && (!Number.isSafeInteger(input.expiresAt) || input.expiresAt<=Date.now()))throw new ForbiddenException('Einrichtungssitzung abgelaufen');};
  authorized();
  const principal = state.principals.find(
    (p) =>
      p.id === input.membershipId &&
      p.issuer === input.issuer &&
      p.subject === input.subject &&
      p.role === input.role &&
      p.state === 'setup-only',
  );
  const owner =
    principal?.role === 'owner' &&
    state.owner?.issuer === input.issuer &&
    state.owner.subject === input.subject;
  if (
    !principal ||
    !["owner","main-manager","manager"].includes(input.role) ||
    authority.schema!==1 ||
    (!owner && !state.onboarding?.ownerCompletedAt) ||
    !Number.isSafeInteger(input.contactId) ||
    input.contactId < 1 ||
    !Number.isSafeInteger(authority.authorityRevision) ||
    authority.authorityRevision >= Number.MAX_SAFE_INTEGER - 2 ||
    !Number.isSafeInteger(authority.supportRevision) ||
    authority.supportRevision < 1 || authority.supportRevision >= Number.MAX_SAFE_INTEGER-2 ||
    !Array.isArray(authority.users) ||
    !['active', 'provisioning'].includes(definition.status) ||
    authority.identityRealm !== input.issuer ||
    (definition.status === 'active' && authority.status !== 'active') ||
    (definition.status === 'provisioning' && !owner)
  )
    throw new ForbiddenException('Einrichtungsfreigabe nicht erlaubt');
  const db = client.db(database),
    opts = { session, maxTimeMS: 3000 };
  const proof = await db
    .collection('tenantManagerSetupProofs')
    .findOne({ _id: input.proofId as never }, opts);
  if (
    !proof ||
    proof.version !== 1 ||
    proof.consumedAt ||
    !Number.isSafeInteger(proof.expiresAt) ||
    proof.expiresAt <= Date.now() ||
    proof.expiresAt > Date.now() + 180000 ||
    proof.environment !== definition.environment ||
    proof.tenantId !== definition.id ||
    proof.configRevision !== definition.configRevision ||
    proof.mongoReference !== definition.secretReferences?.mongoUri ||
    proof.membershipId !== input.membershipId ||
    proof.issuer !== input.issuer ||
    proof.subject !== input.subject ||
    proof.contactId !== input.contactId ||
    proof.accountReference !== input.accountReference ||
    !Array.isArray(proof.sources) ||
    proof.sources.length !== 2
  )
    throw new ConflictException('Einrichtungsprüfung abgelaufen oder geändert');
  if (new Set(proof.sources.map((s: Document) => s.collection)).size !== 2)
    throw new ConflictException('Ungültige Einrichtungsprüfung');
  for (const source of proof.sources) {
    authorized();
    if (
      !/^[A-Za-z0-9_-]{1,63}$/.test(source.database) ||
      source.database === database ||
      !['settings', 'integration_sessions'].includes(source.collection) ||
      !source.expected ||
      !source.replacement ||
      !source.expected.envelope ||
      !source.replacement.envelope ||
      JSON.stringify(source.expected.envelope) ===
        JSON.stringify(source.replacement.envelope) ||
      source.expected.id !== source.replacement.id ||
      (source.collection === 'settings' &&
        (source.expected.id !== 42 ||
          source.expected.hash !== source.replacement.hash)) ||
      (source.collection === 'integration_sessions' &&
        source.expected.revision !== source.replacement.revision)
    )
      throw new ConflictException('Ungültige Einrichtungsprüfung');
    // Fresh authenticated ciphertext makes this a real write lock, not a no-op read fence.
    // The exact old encrypted document is the predicate, so concurrent config changes conflict.
    const result = await client
      .db(source.database)
      .collection(source.collection)
      .replaceOne(source.expected, source.replacement, opts);
    if (result.matchedCount !== 1)
      throw new ConflictException(
        'Vereinsdaten oder Bexio-Verbindung wurden geändert',
      );
  }
  const matches = authority.users.filter(
    (g: Document) => g.issuer === input.issuer && g.subject === input.subject,
  );
  if(matches.length===0 && authority.users.length>=512)throw new ConflictException('Maximale Anzahl Vereinsfreigaben erreicht');
  if (
    matches.length > 1 ||
    (matches.length === 1 &&
      (matches[0].status !== 'active' ||
        matches[0].contactId !== input.contactId ||
        !Number.isSafeInteger(matches[0].revision) ||
        matches[0].revision < 1 ||
        matches[0].revision >= Number.MAX_SAFE_INTEGER - 2 ||
        !Array.isArray(matches[0].permissions) || matches[0].permissions.length>128 || new Set(matches[0].permissions).size!==matches[0].permissions.length || matches[0].permissions.some((p:unknown)=>typeof p!=="string" || !/^club:[a-z][a-z0-9:._-]{0,127}$/.test(p))))
  )
    throw new ConflictException(
      'Bestehende Zugriffsfreigabe muss zuerst geprüft werden',
    );
  const grant = matches.length
    ? { ...matches[0], revision: matches[0].revision + 1 }
    : {
        issuer: input.issuer,
        subject: input.subject,
        status: 'active',
        revision: 1,
        contactId: input.contactId,
        permissions: [...tenantPermissionCatalog],
      };
  const users = matches.length
    ? authority.users.map((u: Document) =>
        u.issuer === input.issuer && u.subject === input.subject ? grant : u,
      )
    : [...authority.users, grant];
  authorized();
  const changed = await db
    .collection('tenantRuntimeAuthorities')
    .updateOne(
      {
        environment: definition.environment,
        tenantId: definition.id,
        configRevision: definition.configRevision,
        authorityRevision: authority.authorityRevision,
      },
      {
        $set: { status: 'active', users },
        $inc: { authorityRevision: 1, supportRevision: 1 },
      },
      opts,
    );
  if (changed.matchedCount !== 1)
    throw new ConflictException('Zugriffsfreigabe wurde geändert');
  if (definition.status === 'provisioning') {
    const activated = await db
      .collection('tenantDefinitions')
      .updateOne(
        {
          environment: definition.environment,
          id: definition.id,
          configRevision: definition.configRevision,
          status: 'provisioning',
        },
        { $set: { status: 'active' } },
        opts,
      );
    if (activated.matchedCount !== 1)
      throw new ConflictException('Verein wurde geändert');
  }
  const consumed = await db
    .collection('tenantManagerSetupProofs')
    .updateOne(
      { _id: input.proofId as never, consumedAt: { $exists: false } },
      { $set: { consumedAt: new Date().toISOString() } },
      opts,
    );
  if (consumed.matchedCount !== 1)
    throw new ConflictException('Prüfung bereits verwendet');
  authorized();
}
