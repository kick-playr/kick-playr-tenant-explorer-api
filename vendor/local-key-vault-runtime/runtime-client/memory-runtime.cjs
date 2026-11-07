"use strict";
const { createHash } = require("node:crypto");
const pin = (value) =>
  createHash("sha256").update(value).digest("hex").slice(0, 32);
const attributes = Object.freeze({
  enabled: true,
  created: 0,
  updated: 0,
  recoveryLevel: "Purgeable",
});
function createMemoryRuntime(source, applicationId, environment) {
  let initialized = false,
    closed = false;
  const ensure = () => {
    if (closed || !initialized || !source.status().ready)
      throw Error("Static secrets unavailable");
  };
  const generation = () =>
    parseInt(
      createHash("sha256")
        .update(source.status().revision ?? "initial")
        .digest("hex")
        .slice(0, 10),
      16,
    ) + 1;
  const readKey = (row) => {
    const bytes = Buffer.from(
      row.value,
      row.valueFormat === "hex64" ? "hex" : "base64",
    );
    try {
      if (bytes.length !== 32) throw Error("Invalid encryption key");
      return bytes.toString("base64");
    } finally {
      bytes.fill(0);
    }
  };
  function snapshot(tenant, revision) {
    ensure();
    const context = source.context(tenant === "_shared" ? undefined : tenant),
      values = context.values,
      keySets = [];
    if (tenant !== "_shared") {
      const wrapping = values.filter(
        (r) =>
          r.kind === "encryption-key" &&
          /_WRAPPING_KEY_V[1-9][0-9]*$/.test(r.accessName),
      );
      const stems = new Set(
        wrapping.map((r) =>
          r.accessName.replace(/_WRAPPING_KEY_V[1-9][0-9]*$/, ""),
        ),
      );
      if (stems.size > 1)
        throw Error("Explicit tenant key-set binding is required");
      for (const stem of stems) {
        const rows = wrapping.filter((r) =>
            r.accessName.startsWith(stem + "_WRAPPING_KEY_"),
          ),
          index = values.find((r) => r.accessName === stem + "_INDEX_KEY"),
          control = values.find((r) => r.accessName === stem + "_CONTROL_KEY");
        if (!index || !control) throw Error("Tenant key set unavailable");
        const versions = [];
        let active;
        for (const row of rows) {
          const ring = row.keyVersions ?? [
            {
              versionId: row.versionId,
              state: "active-for-encryption",
              value: row.value,
            },
          ];
          for (const key of ring) {
            const label =
              key.keyLabel ??
              (key.versionId === row.versionId && ring.length === 1
                ? "v" + row.accessName.match(/_V([1-9][0-9]*)$/)[1]
                : key.versionId);
            versions.push({
              keyVersion: label,
              vaultVersion: pin(key.versionId),
              value: readKey({ ...row, value: key.value }),
              attributes,
            });
            if (key.state === "active-for-encryption") active = label;
          }
        }
        if (!active) throw Error("Tenant active key unavailable");
        keySets.push({
          reference: "workflow-local:" + tenant + ":key",
          mappings: {
            wrapping: rows[0].accessName,
            index: index.accessName,
            control: control.accessName,
          },
          currentWrappingVersion: active,
          wrappingVersions: versions,
          index: {
            vaultVersion: pin(index.versionId),
            value: readKey(index),
            attributes,
          },
          control: {
            vaultVersion: pin(control.versionId),
            value: readKey(control),
            attributes,
          },
        });
      }
    }
    const secrets = values
      .filter(
        (r) =>
          r.kind !== "encryption-key" ||
          !keySets.some((k) =>
            Object.values(k.mappings).includes(r.accessName),
          ),
      )
      .map((r) => ({
        mapping: r.accessName,
        purpose:
          "v2-" + createHash("sha256").update(r.resourceId).digest("hex"),
        version: pin(r.versionId),
        value:
          r.kind === "integration"
            ? JSON.stringify(r.value)
            : r.kind === "encryption-key"
              ? readKey(r)
              : r.value,
        attributes,
      }));
    const descriptor = {
      schemaVersion: 1,
      bindingRevision: revision,
      keySets: keySets.map((k) => ({
        reference: k.reference,
        mappings: k.mappings,
        wrappingVersions: k.wrappingVersions.map((v) => ({
          keyVersion: v.keyVersion,
          vaultVersion: v.vaultVersion,
        })),
        currentWrappingVersion: k.currentWrappingVersion,
        indexVersion: k.index.vaultVersion,
        controlVersion: k.control.vaultVersion,
      })),
      secrets: secrets.map(({ mapping, purpose, version }) => ({
        mapping,
        purpose,
        version,
      })),
    };
    const bindingDigest = require("./index.cjs").bindingDigest(descriptor);
    return {
      ...descriptor,
      bindingDigest,
      environment,
      tenant,
      generation: generation(),
      loadedAt: Date.now(),
      keySets,
      secrets,
    };
  }
  function request(s) {
    return {
      schemaVersion: 1,
      bindingRevision: s.bindingRevision,
      bindingDigest: s.bindingDigest,
      keySets: s.keySets.map((k) => ({
        reference: k.reference,
        mappings: k.mappings,
        wrappingVersions: k.wrappingVersions.map((v) => ({
          keyVersion: v.keyVersion,
          vaultVersion: v.vaultVersion,
        })),
        currentWrappingVersion: k.currentWrappingVersion,
        indexVersion: k.index.vaultVersion,
        controlVersion: k.control.vaultVersion,
      })),
      secrets: s.secrets.map(({ mapping, purpose, version }) => ({
        mapping,
        purpose,
        version,
      })),
    };
  }
  return {
    async loadProcess(app, policy) {
      if (app !== applicationId) throw Error("Application mismatch");
      await source.load();
      initialized = true;
      const s = snapshot("_shared", 1),
        mappings = Object.fromEntries(
          s.secrets.map((r) => [r.mapping, r.value]),
        );
      if (
        Object.keys(mappings).some(
          (k) => !policy.allowedMappings.includes(k),
        ) ||
        policy.requiredMappings?.some((k) => !mappings[k])
      )
        throw Error("Process static mappings unavailable");
      return {
        strategy: "LOCAL_KEYVAULT",
        mappings: Object.freeze(mappings),
        snapshot: s,
      };
    },
    async loadTenant(id, revision) {
      return snapshot(id, revision);
    },
    async loadApplication(app) {
      ensure();
      if (app !== applicationId) throw Error("Application mismatch");
      const s = snapshot("_shared", 1);
      return { scope: { environment, tenant: "_shared" }, request: request(s) };
    },
    async loadBindings(app) {
      ensure();
      if (app !== applicationId) throw Error("Application mismatch");
      return {
        schemaVersion: 1,
        applications: {
          [app]: {
            scope: { environment, tenant: "_shared" },
            request: request(snapshot("_shared", 1)),
          },
        },
        tenants: (source.tenantIds?.() ?? []).map((id) => ({
          scope: { environment, tenant: id },
          request: request(snapshot(id, 1)),
        })),
      };
    },
    async refreshBindings(app) {
      return this.loadBindings(app);
    },
    async loadTenantBinding(app, id) {
      ensure();
      if (app !== applicationId) throw Error("Application mismatch");
      return {
        scope: { environment, tenant: id },
        request: request(snapshot(id, 1)),
      };
    },
    async load(scope, input) {
      if (scope.environment !== environment)
        throw Error("Environment mismatch");
      return snapshot(scope.tenant, input.bindingRevision);
    },
    close() {
      closed = true;
      source.close();
    },
  };
}
module.exports = { createMemoryRuntime };
