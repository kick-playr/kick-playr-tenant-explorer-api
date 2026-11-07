"use strict";
const freeze = (value) => {
  if (value && typeof value === "object") {
    for (const v of Object.values(value)) freeze(v);
    Object.freeze(value);
  }
  return value;
};
function createBootstrapClient(options) {
  const url = new URL(options.url);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !["https:", "http:"].includes(url.protocol) ||
    (url.protocol === "http:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
  )
    throw Error("Invalid Vault bootstrap URL");
  if (
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(options.applicationId) ||
    !/^[a-z][a-z0-9-]{0,31}$/.test(options.environment) ||
    !/^[A-Za-z0-9_-]{43}$/.test(options.grant)
  )
    throw Error("Invalid Vault bootstrap configuration");
  const interval = options.refreshIntervalMs ?? 60000;
  if (!Number.isFinite(interval) || interval < 60000)
    throw Error("Vault refresh interval must be at least one minute");
  const now = options.now ?? (() => performance.now()),
    fetcher = options.fetch ?? globalThis.fetch,
    env = options.env ?? process.env;
  const schedule =
    options.schedule ??
    ((fn, delay) => {
      const timer = setTimeout(fn, delay);
      if (status().ready) timer.unref?.();
      return () => clearTimeout(timer);
    });
  let current,
    connected = false,
    closed = false,
    inflight,
    last = -Infinity,
    cancel,
    etag,
    waiters = [],
    started = false;
  let waitingForKeys = false;
  let instance;
  let activeController;
  const keys = new Map();
  function wipeKeys() {
    for (const bytes of keys.values()) bytes.fill(0);
    keys.clear();
  }
  function stageKeys(next) {
    for (const context of [next.application, ...Object.values(next.tenants)])
      for (const row of context.values)
        if (row.kind === "encryption-key")
          for (const key of row.keyVersions ?? [
            { versionId: row.versionId, value: row.value },
          ]) {
            const id = row.resourceId + "/" + key.versionId,
              bytes = Buffer.from(
                key.value,
                row.valueFormat === "hex64" ? "hex" : "base64",
              );
            if (bytes.length !== 32) throw Error("Invalid encryption key");
            if (keys.has(id)) bytes.fill(0);
            else keys.set(id, bytes);
          }
  }
  const installed = new Map();
  const endpoint = new URL("/v2/bootstrap", url);
  endpoint.searchParams.set("applicationId", options.applicationId);
  endpoint.searchParams.set("environment", options.environment);
  function clearEnv() {
    for (const [key, value] of installed)
      if (env[key] === value) delete env[key];
    installed.clear();
  }
  function status() {
    return Object.freeze({
      ready: !closed && current?.application.ready === true,
      connected,
      message: waitingForKeys
        ? "Waiting for crypto adapter key installation"
        : connected
          ? current?.application.reason
          : "Key Vault is not connected",
      revision: current?.revision,
    });
  }
  function publish(next) {
    clearEnv();
    current = next;
    if (!next) wipeKeys();
    else {
      const retained = new Set();
      for (const context of [next.application, ...Object.values(next.tenants)])
        for (const row of context.values)
          if (row.kind === "encryption-key")
            for (const key of row.keyVersions ?? [{ versionId: row.versionId }])
              retained.add(row.resourceId + "/" + key.versionId);
      for (const [id, bytes] of keys)
        if (!retained.has(id)) {
          bytes.fill(0);
          keys.delete(id);
        }
    }
    for (const row of next?.application.ready ? next.application.values : []) {
      if (row.kind === "secret" || row.kind === "encryption-key") {
        env[row.accessName] = row.value;
        installed.set(row.accessName, row.value);
      }
    }
    if (status().ready) {
      for (const waiter of waiters) waiter.resolve();
      waiters = [];
    }
  }
  function validate(data) {
    data = structuredClone(data);
    if (
      !data ||
      data.format !== 2 ||
      data.applicationId !== options.applicationId ||
      data.environment !== options.environment ||
      typeof data.revision !== "string" ||
      !data.revision ||
      !data.tenants ||
      typeof data.tenants !== "object" ||
      Array.isArray(data.tenants)
    )
      throw Error("Invalid bootstrap snapshot");
    if (
      data.application?.ready &&
      options.requiredMappings?.some(
        (name) =>
          !data.application.values?.some((row) => row.accessName === name),
      )
    ) {
      data.application = {
        ready: false,
        reason: "Required application static secrets unavailable",
        values: [],
      };
    }
    const contexts = [data.application, ...Object.values(data.tenants)];
    if (contexts.length > 1001) throw Error("Bootstrap view exceeds limits");
    for (const tenant of Object.keys(data.tenants))
      if (
        !/^[a-z0-9](?:[a-z0-9-]{0,50}[a-z0-9])?$/.test(tenant) ||
        ["__proto__", "constructor", "prototype"].includes(tenant)
      )
        throw Error("Invalid bootstrap tenant");
    for (const context of contexts) {
      if (
        !context ||
        typeof context.ready !== "boolean" ||
        !Array.isArray(context.values) ||
        context.values.length > 10000 ||
        (!context.ready && context.values.length)
      )
        throw Error("Invalid bootstrap context");
      const seen = new Set();
      for (const row of context.values) {
        if (
          !row ||
          !["secret", "encryption-key", "integration"].includes(row.kind) ||
          !["text", "base64", "hex64"].includes(row.valueFormat) ||
          typeof row.accessName !== "string" ||
          !/^[A-Z][A-Z0-9_]{0,127}$/.test(row.accessName) ||
          seen.has(row.accessName) ||
          /^(NEXT_PUBLIC_|PUBLIC_|VITE_|NODE_|NPM_|VAULT_|LOCAL_KEYVAULT_|LD_|DYLD_)/.test(
            row.accessName,
          ) ||
          ["PATH", "HOME", "SHELL", "SECRETS_KEYS_STRATEGY"].includes(
            row.accessName,
          ) ||
          !["resourceId", "versionId", "name", "schemaIdentity"].every(
            (k) => typeof row[k] === "string" && row[k].length > 0,
          )
        )
          throw Error("Invalid bootstrap resource");
        if (row.kind === "encryption-key") {
          const ring = row.keyVersions ?? [
            {
              versionId: row.versionId,
              state: "active-for-encryption",
              value: row.value,
            },
          ];
          if (!Array.isArray(ring) || ring.length > 256 || ring.length === 0)
            throw Error("Invalid key ring");
          const versions = new Set();
          for (const key of ring) {
            if (
              !["prepared", "active-for-encryption", "decrypt-only"].includes(
                key.state,
              ) ||
              typeof key.versionId !== "string" ||
              versions.has(key.versionId) ||
              typeof key.value !== "string" ||
              !["base64", "hex64"].includes(row.valueFormat)
            )
              throw Error("Invalid key ring");
            versions.add(key.versionId);
            const bytes = Buffer.from(
              key.value,
              row.valueFormat === "hex64" ? "hex" : "base64",
            );
            try {
              if (
                bytes.length !== 32 ||
                (row.valueFormat === "hex64"
                  ? !/^[a-fA-F0-9]{64}$/.test(key.value)
                  : bytes.toString("base64") !== key.value)
              )
                throw Error("Invalid encryption key");
            } finally {
              bytes.fill(0);
            }
          }
        }
        if (row.kind === "integration")
          require("./integration-validation.cjs").validateIntegration(row);
        seen.add(row.accessName);
        if (
          row.kind === "integration"
            ? !row.value ||
              typeof row.value !== "object" ||
              Array.isArray(row.value)
            : typeof row.value !== "string"
        )
          throw Error("Invalid bootstrap value");
      }
    }
    return freeze(structuredClone(data));
  }
  async function request() {
    last = now();
    const controller = new AbortController();
    activeController = controller;
    const timeout = setTimeout(
      () => controller.abort(),
      options.timeoutMs ?? 15000,
    );
    timeout.unref?.();
    let authoritative = false;
    try {
      if (options.registerInstances && !instance) {
        const registration = await fetcher(
          new URL("/v2/instances", url).toString(),
          {
            method: "POST",
            headers: {
              authorization: "Bearer " + options.grant,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              applicationId: options.applicationId,
              environment: options.environment,
            }),
            signal: controller.signal,
            redirect: "error",
          },
        );
        if (registration.status === 401 || registration.status === 403) {
          publish(undefined);
          connected = true;
          return;
        }
        if (registration.status !== 201 && registration.status !== 200)
          throw Error("Instance registration unavailable");
        const registered = await registration.json();
        if (
          typeof registered.instanceId !== "string" ||
          !/^[A-Za-z0-9-]{1,128}$/.test(registered.instanceId) ||
          typeof registered.password !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(registered.password)
        )
          throw Error("Invalid instance registration");
        if (closed) return;
        instance = registered;
      }
      const res = await fetcher(endpoint.toString(), {
        method: "GET",
        headers: {
          authorization: "Bearer " + options.grant,
          ...(instance
            ? {
                "x-vault-instance-id": instance.instanceId,
                "x-vault-instance-password": instance.password,
              }
            : {}),
          ...(etag ? { "if-none-match": etag } : {}),
        },
        signal: controller.signal,
        redirect: "error",
        cache: "no-store",
      });
      if (closed) return;
      if (res.status === 401 || res.status === 403) {
        connected = true;
        etag = undefined;
        const previous = current;
        publish(undefined);
        await options.onChange?.(undefined, previous);
        return;
      }
      if (res.status === 304) {
        if (!current) throw Error("Missing bootstrap baseline");
        connected = true;
        return;
      }
      if (res.status !== 200) throw Error("Vault unavailable");
      let raw;
      if (typeof res.text === "function") {
        const text = await res.text();
        if (Buffer.byteLength(text) > 8 * 1024 * 1024)
          throw Error("Bootstrap view exceeds limits");
        raw = JSON.parse(text);
      } else raw = await res.json();
      const next = validate(raw);
      authoritative = true;
      if (closed) return;
      connected = true;
      if (next.revision !== current?.revision) {
        await options.onChange?.(next, current);
        if (closed) return;
        stageKeys(next);
      }
      let unsupportedPrepared = false;
      if (instance)
        for (const context of [
          next.application,
          ...Object.values(next.tenants),
        ])
          for (const row of context.values)
            for (const key of row.keyVersions ?? [])
              if (key.state === "prepared" && key.rotationId) {
                if ((await options.acknowledgeKey?.(row, key)) !== true) {
                  unsupportedPrepared = true;
                  continue;
                }
                if (closed) return;
                const ack = await fetcher(
                  new URL("/v2/instances/acknowledge", url).toString(),
                  {
                    method: "POST",
                    headers: {
                      authorization: "Bearer " + options.grant,
                      "content-type": "application/json",
                    },
                    body: JSON.stringify({
                      applicationId: options.applicationId,
                      environment: options.environment,
                      ...instance,
                      rotationId: key.rotationId,
                      versionId: key.versionId,
                    }),
                    signal: controller.signal,
                    redirect: "error",
                  },
                );
                if (ack.status !== 201 && ack.status !== 200)
                  throw Error("Key acknowledgement unavailable");
              }
      if (closed) return;
      waitingForKeys = unsupportedPrepared;
      if (unsupportedPrepared && !current) return;
      if (next.revision !== current?.revision) publish(next);
      etag = next.revision;
    } catch {
      if (closed) return;
      if (authoritative) {
        // A successful authority response supersedes the old authorization even
        // when local composition or installation fails. Transport outages alone
        // retain the last good snapshot.
        const previous = current;
        etag = undefined;
        publish(undefined);
        connected = true;
        try { await options.onChange?.(undefined, previous); } catch {}
        options.onDiagnostic?.("Application static secrets unavailable");
      } else {
        connected = false;
        options.onDiagnostic?.("Key Vault is not connected");
      }
    } finally {
      clearTimeout(timeout);
      if (activeController === controller) activeController = undefined;
    }
  }
  function refresh() {
    if (closed) return Promise.resolve();
    if (inflight) return inflight;
    if (now() - last < interval) return Promise.resolve();
    inflight = request().finally(() => {
      inflight = undefined;
      if (started && !closed) {
        cancel?.();
        cancel = schedule(
          () => void refresh(),
          Math.max(0, interval - (now() - last)),
        );
      }
    });
    return inflight;
  }
  function start() {
    if (closed) return Promise.reject(Error("Bootstrap client closed"));
    started = true;
    const ready = status().ready
      ? Promise.resolve()
      : new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    if (!inflight && now() - last < interval) {
      cancel?.();
      cancel = schedule(() => void refresh(), Math.max(0, interval - (now() - last)));
    } else void refresh();
    return ready;
  }
  function application() {
    if (!status().ready) throw Error("Application static secrets unavailable");
    return current.application;
  }
  function tenant(id) {
    if (
      !status().ready ||
      !Object.hasOwn(current.tenants, id) ||
      !current.tenants[id].ready
    )
      throw Error("Tenant static secrets unavailable");
    return current.tenants[id];
  }
  function close() {
    if (closed) return;
    closed = true;
    activeController?.abort();
    cancel?.();
    clearEnv();
    current = undefined;
    wipeKeys();
    etag = undefined;
    for (const waiter of waiters)
      waiter.reject(Error("Bootstrap client closed"));
    waiters = [];
  }
  return Object.freeze({
    start,
    refresh,
    status,
    application,
    tenant,
    close,
    key: (resourceId, versionId) => {
      if (closed || !keys.has(resourceId + "/" + versionId))
        throw Error("Local key unavailable");
      return Buffer.from(keys.get(resourceId + "/" + versionId));
    },
    tenantIds: () => {
      if (!status().ready) throw Error("Static secrets unavailable");
      return Object.keys(current.tenants);
    },
  });
}
module.exports = { createBootstrapClient };
