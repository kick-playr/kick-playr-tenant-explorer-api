"use strict";
const {
  randomBytes,
  randomUUID,
  createCipheriv,
  createDecipheriv,
} = require("node:crypto");
function assertRuntimeDatabase(database, tenantId) {
  if (
    typeof tenantId !== "string" ||
    !/^[a-z0-9](?:[a-z0-9-]{0,50}[a-z0-9])?$/.test(tenantId) ||
    ["key-vault", "control"].includes(tenantId) ||
    database !== tenantId + "-kick-playr"
  )
    throw Error("Runtime credentials require the tenant database");
}
const aad = (c) =>
  Buffer.from(
    JSON.stringify([
      1,
      c.tenantId,
      c.environment,
      c.integrationId,
      c.authorityGeneration,
      c.revision,
      c.staticVersion,
    ]),
  );
function validate(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !Object.keys(value).every((k) =>
      [
        "accessToken",
        "refreshToken",
        "idToken",
        "tokenType",
        "expiresAt",
      ].includes(k),
    ) ||
    typeof value.accessToken !== "string" ||
    !value.accessToken ||
    value.accessToken.length > 32768 ||
    typeof value.refreshToken !== "string" ||
    !value.refreshToken ||
    value.refreshToken.length > 32768 ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt < 0 ||
    ("idToken" in value &&
      (typeof value.idToken !== "string" || value.idToken.length > 32768)) ||
    ("tokenType" in value &&
      (typeof value.tokenType !== "string" || value.tokenType.length > 128)) ||
    JSON.stringify(value).length > 65536
  )
    throw Error("Invalid runtime credential payload");
  return value;
}
function sealRuntime(context, value, key, keyVersion) {
  validate(value);
  if (!Buffer.isBuffer(key) || key.length !== 32 || !keyVersion)
    throw Error("Runtime key unavailable");
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key, iv),
    plain = Buffer.from(JSON.stringify(value));
  try {
    cipher.setAAD(aad(context));
    return {
      format: 1,
      keyVersion,
      iv: iv.toString("base64"),
      tag: undefined,
      ciphertext: Buffer.concat([
        cipher.update(plain),
        cipher.final(),
      ]).toString("base64"),
      ...{ tag: cipher.getAuthTag().toString("base64") },
    };
  } finally {
    plain.fill(0);
  }
}
function openRuntime(context, envelope, keys) {
  try {
    const key = keys.get(envelope.keyVersion);
    if (!key || key.length !== 32 || envelope.format !== 1) throw Error();
    const iv = Buffer.from(envelope.iv, "base64"),
      tag = Buffer.from(envelope.tag, "base64");
    if (iv.length !== 12 || tag.length !== 16) throw Error();
    const cipher = createDecipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad(context));
    cipher.setAuthTag(tag);
    const plain = Buffer.concat([
      cipher.update(Buffer.from(envelope.ciphertext, "base64")),
      cipher.final(),
    ]);
    try {
      return validate(JSON.parse(plain.toString("utf8")));
    } finally {
      plain.fill(0);
    }
  } catch {
    throw Error("Runtime credentials unavailable");
  }
}
function validateMetadata(input) {
  const value = JSON.parse(JSON.stringify(input));
  if (
    !value ||
    Object.keys(value).sort().join() !==
      "capabilities,connectionId,provider,purpose,schema,securityEpoch" ||
    value.schema !== 1 ||
    ![value.connectionId, value.provider, value.purpose].every(
      (v) =>
        typeof v === "string" && /^[a-zA-Z0-9][a-zA-Z0-9:_.-]{0,127}$/.test(v),
    ) ||
    !Number.isSafeInteger(value.securityEpoch) ||
    value.securityEpoch < 1 ||
    !Array.isArray(value.capabilities) ||
    value.capabilities.length > 64 ||
    new Set(value.capabilities).size !== value.capabilities.length ||
    !value.capabilities.every(
      (v) =>
        typeof v === "string" && /^[a-zA-Z0-9][a-zA-Z0-9:_.-]{0,127}$/.test(v),
    )
  )
    throw Error("Invalid runtime lifecycle metadata");
  return Object.freeze({
    ...value,
    capabilities: Object.freeze([...value.capabilities]),
  });
}
function validateMetadataTransition(old, next) {
  const previous = validateMetadata(old);
  if (
    ["connectionId", "provider", "purpose"].some(
      (k) => previous[k] !== next[k],
    ) ||
    next.securityEpoch <= previous.securityEpoch
  )
    throw Error("Invalid runtime lifecycle transition");
}
function createIntegrationRuntime(options) {
  const {
    db,
    tenantId,
    environment,
    integrationId,
    staticVersion,
    accountReference,
  } = options;
  assertRuntimeDatabase(db.databaseName, tenantId);
  if (
    !/^[a-z][a-z0-9-]{0,31}$/.test(environment) ||
    typeof integrationId !== "string" ||
    !integrationId ||
    integrationId.length > 128 ||
    !staticVersion ||
    !accountReference
  )
    throw Error("Invalid integration runtime identity");
  const credentials = db.collection("integration_runtime_credentials"),
    operations = db.collection("integration_refresh_operations"),
    scope = { tenantId, environment, integrationId },
    id = environment + "/" + integrationId;
  const context = (row) => ({
    ...scope,
    authorityGeneration: row.authorityGeneration,
    revision: row.revision,
    staticVersion: row.staticVersion,
  });
  const fail = (code) => Object.assign(Error(code), { code });
  async function transaction(work) {
    const session = db.client.startSession();
    try {
      return await session.withTransaction(
        async () => {
          await options.beforeWrite?.(session);
          const result = await work(session);
          await options.beforeWrite?.(session);
          return result;
        },
        {
          readConcern: { level: "snapshot" },
          writeConcern: { w: "majority" },
          readPreference: "primary",
        },
      );
    } finally {
      await session.endSession();
    }
  }
  async function read(metadataOnly = false, session) {
    const row = await credentials.findOne(
      { _id: id, ...scope },
      {
        ...(metadataOnly ? { projection: { value: 0 } } : {}),
        ...(session ? { session } : {}),
      },
    );
    if (
      !row ||
      row.status !== "active" ||
      row.staticVersion !== staticVersion ||
      row.accountReference !== accountReference
    )
      throw fail("reauthorization-required");
    return row;
  }
  async function token() {
    const row = await read(!!options.cache);
    if (row.expiresAt <= Date.now())
      throw fail(
        row.operation ? "reconciliation-required" : "refresh-required",
      );
    const cacheKey = JSON.stringify([
      tenantId,
      environment,
      integrationId,
      row.authorityGeneration,
      row.revision,
      row.staticVersion,
    ]);
    if (options.cache)
      try {
        const cached = await options.cache.get(cacheKey);
        if (cached) return openRuntime(context(row), cached, options.keys);
      } catch {}
    const actual = row.value
      ? row
      : await credentials.findOne({
          _id: id,
          ...scope,
          authorityGeneration: row.authorityGeneration,
          revision: row.revision,
          status: "active",
          staticVersion,
        });
    if (!actual?.value) throw fail("authority-conflict");
    const value = openRuntime(context(actual), actual.value, options.keys);
    if (options.cache)
      try {
        await options.cache.set(
          cacheKey,
          actual.value,
          Math.max(0, actual.expiresAt - Date.now()),
        );
      } catch {}
    return value;
  }
  async function reconnect(
    value,
    verifiedAccountReference,
    expectedGeneration,
    lifecycle,
  ) {
    validate(value);
    const metadata =
      lifecycle?.metadata === undefined
        ? undefined
        : validateMetadata(lifecycle.metadata);
    if (verifiedAccountReference !== accountReference)
      throw fail("provider-account-mismatch");
    return transaction(async (session) => {
      const old = await credentials.findOne({ _id: id, ...scope }, { session });
      if (
        (old?.authorityGeneration ?? 0) !== expectedGeneration ||
        (lifecycle?.expectedRevision !== undefined &&
          (old?.revision ?? 0) !== lifecycle.expectedRevision)
      )
        throw fail("authority-conflict");
      if (metadata && old?.metadata)
        validateMetadataTransition(old.metadata, metadata);
      const next = {
        _id: id,
        ...scope,
        authorityGeneration: expectedGeneration + 1,
        revision: (old?.revision ?? 0) + 1,
        staticVersion,
        accountReference,
        status: "active",
        expiresAt: value.expiresAt,
        operation: null,
        ...((metadata ?? old?.metadata)
          ? { metadata: metadata ?? old.metadata }
          : {}),
      };
      next.value = sealRuntime(
        context(next),
        value,
        options.keys.get(options.activeKeyVersion),
        options.activeKeyVersion,
      );
      if (old) {
        const result = await credentials.replaceOne(
          {
            _id: id,
            ...scope,
            authorityGeneration: expectedGeneration,
            revision: old.revision,
          },
          next,
          { session },
        );
        if (result.matchedCount !== 1) throw fail("authority-conflict");
      } else await credentials.insertOne(next, { session });
      if (old?.operation)
        await operations.updateOne(
          { _id: old.operation },
          { $set: { status: "superseded", supersededAt: Date.now() } },
          { session },
        );
      return {
        revision: next.revision,
        authorityGeneration: next.authorityGeneration,
      };
    });
  }
  async function refresh(provider, expected) {
    const row = await read();
    if (
      expected &&
      (row.authorityGeneration !== expected.authorityGeneration ||
        row.revision !== expected.revision)
    )
      throw fail("authority-conflict");
    if (row.expiresAt > Date.now() && !expected?.force)
      return openRuntime(context(row), row.value, options.keys);
    if (row.operation) throw fail("reconciliation-required");
    const operationId = randomUUID();
    await transaction(async (session) => {
      const changed = await credentials.updateOne(
        {
          _id: id,
          ...scope,
          revision: row.revision,
          authorityGeneration: row.authorityGeneration,
          staticVersion,
          operation: null,
          status: "active",
        },
        { $set: { operation: operationId } },
        { session },
      );
      if (changed.matchedCount !== 1) throw fail("refresh-in-progress");
      await operations.insertOne(
        {
          _id: operationId,
          ...scope,
          authorityGeneration: row.authorityGeneration,
          revision: row.revision,
          staticVersion,
          phase: "reserved",
          createdAt: Date.now(),
        },
        { session },
      );
    });
    // Durable dispatch marker precedes the external call. Unknown outcome is never retried automatically.
    await transaction(async (session) => {
      const guarded = await credentials.updateOne(
        {
          _id: id,
          ...scope,
          revision: row.revision,
          authorityGeneration: row.authorityGeneration,
          staticVersion,
          operation: operationId,
          status: "active",
        },
        { $inc: { dispatchFence: 1 } },
        { session },
      );
      if (guarded.matchedCount !== 1) throw fail("authority-conflict");
      const dispatched = await operations.updateOne(
        { _id: operationId, phase: "reserved" },
        { $set: { phase: "dispatched", dispatchedAt: Date.now() } },
        { session },
      );
      if (dispatched.matchedCount !== 1) throw fail("reconciliation-required");
    });
    let value;
    try {
      value = validate(
        await provider(openRuntime(context(row), row.value, options.keys)),
      );
    } catch {
      throw fail("reauthorization-required");
    }
    const nextContext = { ...context(row), revision: row.revision + 1 },
      sealed = sealRuntime(
        nextContext,
        value,
        options.keys.get(options.activeKeyVersion),
        options.activeKeyVersion,
      );
    try {
      await transaction(async (session) => {
        await operations.updateOne(
          { _id: operationId, phase: "dispatched" },
          {
            $set: {
              phase: "result",
              value: sealed,
              expiresAt: value.expiresAt,
            },
          },
          { session },
        );
        const committed = await credentials.updateOne(
          {
            _id: id,
            ...scope,
            revision: row.revision,
            authorityGeneration: row.authorityGeneration,
            staticVersion,
            operation: operationId,
            status: "active",
          },
          {
            $set: {
              value: sealed,
              expiresAt: value.expiresAt,
              operation: null,
              lastOperationId: operationId,
            },
            $inc: { revision: 1 },
          },
          { session },
        );
        if (committed.matchedCount !== 1) throw fail("authority-conflict");
        await operations.updateOne(
          { _id: operationId },
          { $set: { phase: "committed" } },
          { session },
        );
      });
    } catch {
      const current = await credentials.findOne({ _id: id, ...scope });
      if (current?.lastOperationId !== operationId)
        throw fail("reconciliation-required");
    }
    return value;
  }
  async function recoverReserved(operationId) {
    return transaction(async (session) => {
      const row = await read(false, session),
        operation = await operations.findOne(
          {
            _id: operationId,
            ...scope,
            phase: "reserved",
            authorityGeneration: row.authorityGeneration,
            revision: row.revision,
            staticVersion,
          },
          { session },
        );
      if (!operation || row.operation !== operationId)
        throw fail("reconciliation-required");
      const recoveredValue = sealRuntime(
        { ...context(row), authorityGeneration: row.authorityGeneration + 1 },
        openRuntime(context(row), row.value, options.keys),
        options.keys.get(options.activeKeyVersion),
        options.activeKeyVersion,
      );
      const guarded = await credentials.updateOne(
        {
          _id: id,
          ...scope,
          operation: operationId,
          authorityGeneration: row.authorityGeneration,
          revision: row.revision,
        },
        {
          $set: { operation: null, value: recoveredValue },
          $inc: { authorityGeneration: 1 },
        },
        { session },
      );
      if (guarded.matchedCount !== 1) throw fail("authority-conflict");
      await operations.updateOne(
        { _id: operationId, phase: "reserved" },
        { $set: { phase: "aborted-before-dispatch" } },
        { session },
      );
      return { recovered: true };
    });
  }
  async function synchronizeStatic(expectedGeneration) {
    return transaction(async (session) => {
      const row = await credentials.findOne({ _id: id, ...scope }, { session });
      if (!row)
        return { status: "reauthorization-required", authorityGeneration: 0 };
      if (row.authorityGeneration !== expectedGeneration)
        throw fail("authority-conflict");
      if (
        row.staticVersion === staticVersion &&
        row.accountReference === accountReference
      )
        return {
          status: row.status,
          authorityGeneration: row.authorityGeneration,
        };
      await operations.insertOne(
        {
          _id: randomUUID(),
          ...scope,
          authorityGeneration: row.authorityGeneration,
          revision: row.revision,
          staticVersion: row.staticVersion,
          value: row.value,
          phase: "superseded-static",
          createdAt: Date.now(),
        },
        { session },
      );
      const changed = await credentials.updateOne(
        {
          _id: id,
          ...scope,
          authorityGeneration: expectedGeneration,
          revision: row.revision,
        },
        {
          $set: {
            staticVersion,
            accountReference,
            status: "reauthorization-required",
            operation: null,
          },
          $unset: { value: "" },
          $inc: { authorityGeneration: 1, revision: 1 },
        },
        { session },
      );
      if (changed.matchedCount !== 1) throw fail("authority-conflict");
      if (row.operation)
        await operations.updateOne(
          { _id: row.operation },
          { $set: { status: "superseded" } },
          { session },
        );
      return {
        status: "reauthorization-required",
        authorityGeneration: expectedGeneration + 1,
      };
    });
  }
  async function inspect() {
    const row = await credentials.findOne(
      { _id: id, ...scope },
      { projection: { value: 0 } },
    );
    if (!row) return null;
    if (
      !Number.isSafeInteger(row.revision) ||
      row.revision < 1 ||
      !Number.isSafeInteger(row.authorityGeneration) ||
      row.authorityGeneration < 1 ||
      !["active", "suspended", "revoked", "reauthorization-required"].includes(
        row.status,
      )
    )
      throw fail("authority-conflict");
    return Object.freeze({
      expiresAt: row.expiresAt,
      authorityGeneration: row.authorityGeneration,
      revision: row.revision,
      staticVersion: row.staticVersion,
      accountReference: row.accountReference,
      status: row.status,
      operation: row.operation ?? null,
      ...(row.metadata ? { metadata: validateMetadata(row.metadata) } : {}),
    });
  }
  async function setLifecycle(
    expectedGeneration,
    expectedRevision,
    status,
    metadata,
  ) {
    if (!["active", "suspended"].includes(status))
      throw fail("invalid-lifecycle");
    const nextMetadata = validateMetadata(metadata);
    return transaction(async (session) => {
      const old = await credentials.findOne({ _id: id, ...scope }, { session });
      if (
        !old ||
        old.authorityGeneration !== expectedGeneration ||
        old.revision !== expectedRevision ||
        old.staticVersion !== staticVersion ||
        old.accountReference !== accountReference ||
        old.operation ||
        !["active", "suspended"].includes(old.status)
      )
        throw fail("authority-conflict");
      if (!old.metadata) throw fail("reauthorization-required");
      validateMetadataTransition(old.metadata, nextMetadata);
      const next = {
        ...old,
        authorityGeneration: old.authorityGeneration + 1,
        revision: old.revision + 1,
        status,
        metadata: nextMetadata,
      };
      next.value = sealRuntime(
        context(next),
        openRuntime(context(old), old.value, options.keys),
        options.keys.get(options.activeKeyVersion),
        options.activeKeyVersion,
      );
      const changed = await credentials.replaceOne(
        {
          _id: id,
          ...scope,
          authorityGeneration: expectedGeneration,
          revision: expectedRevision,
          operation: null,
        },
        next,
        { session },
      );
      if (changed.matchedCount !== 1) throw fail("authority-conflict");
      return {
        revision: next.revision,
        authorityGeneration: next.authorityGeneration,
      };
    });
  }
  return Object.freeze({
    token,
    inspect,
    setLifecycle,
    refresh,
    reconnect,
    recoverReserved,
    synchronizeStatic,
    async revoke(expectedGeneration) {
      return transaction(async (session) => {
        const result = await credentials.updateOne(
          { _id: id, ...scope, authorityGeneration: expectedGeneration },
          {
            $set: { status: "revoked" },
            $inc: { authorityGeneration: 1, revision: 1 },
          },
          { session },
        );
        if (result.matchedCount !== 1) throw fail("authority-conflict");
      });
    },
  });
}
module.exports = {
  assertRuntimeDatabase,
  validateRuntimeMetadata: validateMetadata,
  sealRuntime,
  openRuntime,
  createIntegrationRuntime,
};
