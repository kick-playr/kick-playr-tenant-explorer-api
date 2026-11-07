"use strict";
const { createBootstrapClient } = require("./bootstrap.cjs");
function createServerBootstrap(environment, applicationId, options = {}) {
  if (environment.VAULT_APPLICATION_ID !== applicationId)
    throw Error("Vault application identity mismatch");
  const processValues = {},
    required = options.requiredMappings ?? [];
  let started;
  const client = createBootstrapClient({
    registerInstances: true,
    ...options.clientOptions,
    url: environment.VAULT_URL,
    applicationId,
    environment: environment.VAULT_ENVIRONMENT,
    grant: environment.VAULT_GRANT,
    requiredMappings: required,
    env: options.clientOptions?.env ?? process.env,
    onChange: async (next, previous) => {
      if (next?.application.ready) {
        const names = new Set(next.application.values.map((v) => v.accessName));
        if (required.some((name) => !names.has(name)))
          throw Error("Required application static secrets unavailable");
      }
      await options.onChange?.(next, previous);
    },
    onDiagnostic:
      options.onDiagnostic ??
      ((message) => process.stderr.write(message + "\n")),
  });
  function values(context) {
    return Object.freeze(
      Object.fromEntries(
        context.values
          .filter((v) => v.kind !== "integration")
          .map((v) => [v.accessName, v.value]),
      ),
    );
  }
  function read() {
    const context = client.application();
    return Object.freeze({ ...values(context) });
  }
  return Object.freeze({
    async load() {
      started ??= client.start();
      await started;
      return read();
    },
    refresh: () => client.refresh(),
    status: () => ({
      ...client.status(),
      state: client.status().ready ? "applied" : "blocked",
    }),
    tenant: (id) => values(client.tenant(id)),
    tenantIds: () => client.tenantIds(),
    key: (resourceId, versionId) => client.key(resourceId, versionId),
    integration(tenantId, name) {
      const context = client.tenant(tenantId),
        row = context.values.find(
          (v) =>
            v.kind === "integration" &&
            (v.name === name || v.accessName === name),
        );
      if (!row) throw Error("Integration static secrets unavailable");
      return row;
    },
    context: (tenantId) =>
      tenantId ? client.tenant(tenantId) : client.application(),
    close: () => client.close(),
  });
}
function publicConfiguration(context) {
  if (!context?.ready) throw Error("Public configuration unavailable");
  const values = Object.fromEntries(
      context.values.map((r) => [r.accessName, r.value]),
    ),
    result = {};
  if (values.CLERK_PUBLISHABLE_KEY !== undefined) {
    if (
      typeof values.CLERK_PUBLISHABLE_KEY !== "string" ||
      !/^pk_(?:test|live)_[A-Za-z0-9+/_=-]+$/.test(values.CLERK_PUBLISHABLE_KEY)
    )
      throw Error("Invalid public Clerk configuration");
    result.clerkPublishableKey = values.CLERK_PUBLISHABLE_KEY;
  }
  if (values.API_PUBLIC_ORIGIN !== undefined) {
    const url = new URL(values.API_PUBLIC_ORIGIN);
    if (
      url.origin !== values.API_PUBLIC_ORIGIN ||
      url.username ||
      url.password ||
      !(
        url.protocol === "https:" ||
        (url.protocol === "http:" &&
          (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
            url.hostname.endsWith(".localhost")))
      )
    )
      throw Error("Invalid public API configuration");
    result.apiOrigin = url.origin;
  }
  return Object.freeze(result);
}
module.exports = { createServerBootstrap, publicConfiguration };
