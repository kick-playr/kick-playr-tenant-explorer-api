"use strict";
const Ajv = require("ajv").default;
const { createHash } = require("node:crypto");
const compiled = new Map();
function validateIntegration(row) {
  try {
    if (
      typeof row.schemaIdentity !== "string" ||
      !row.schema ||
      JSON.stringify(row.schema).length > 32768 ||
      JSON.stringify(row.value).length > 65536
    )
      throw Error();
    let nodes = 0;
    const inspect = (value, depth = 0, schema = false, keyspace = false) => {
      if (depth > 16 || ++nodes > 4096) throw Error();
      if (value && typeof value === "object")
        for (const [key, item] of Object.entries(value)) {
          if (
            ["__proto__", "prototype", "constructor"].includes(key) ||
            (schema &&
              !keyspace &&
              [
                "$ref",
                "$dynamicRef",
                "$async",
                "pattern",
                "patternProperties",
                "format",
                "$data",
              ].includes(key)) ||
            (!schema &&
              [
                "accesstoken",
                "refreshtoken",
                "idtoken",
                "sessiontoken",
                "jwt",
                "oauthstate",
                "pkceverifier",
              ].includes(key.replace(/[^a-z0-9]/gi, "").toLowerCase()))
          )
            throw Error();
          inspect(
            item,
            depth + 1,
            schema,
            schema &&
              !keyspace &&
              ["properties", "definitions", "$defs"].includes(key),
          );
        }
    };
    inspect(row.value);
    inspect(row.schema, 0, true);
    const digest = createHash("sha256")
      .update(JSON.stringify(row.schema))
      .digest("hex");
    let prepared = compiled.get(row.schemaIdentity);
    if (prepared && prepared.digest !== digest) throw Error();
    if (!prepared) {
      if (compiled.size >= 512) throw Error();
      const ajv = new Ajv({
        strict: true,
        coerceTypes: false,
        useDefaults: false,
        removeAdditional: false,
        ownProperties: true,
        validateFormats: false,
      });
      for (const keyword of ["x-secret", "x-public"])
        ajv.addKeyword({ keyword, schemaType: "boolean" });
      prepared = { digest, validate: ajv.compile(row.schema) };
      compiled.set(row.schemaIdentity, prepared);
    }
    if (!prepared.validate(row.value)) throw Error();
    return row.value;
  } catch {
    throw Error("Invalid static integration configuration");
  }
}
module.exports = { validateIntegration };
