import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SamlStrategy, resolvePem } from "../src/index.ts";

describe("resolvePem", () => {
  const body = "A".repeat(128);
  const pem = `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;

  it("returns undefined for missing/empty values", () => {
    assert.equal(resolvePem(undefined), undefined);
    assert.equal(resolvePem("   "), undefined);
  });

  it("passes Buffers through untouched", () => {
    const buf = Buffer.from(pem);
    assert.equal(resolvePem(buf), buf);
  });

  it("passes PEM strings through without touching the filesystem", () => {
    assert.equal(resolvePem(pem), pem);
  });

  it("converts literal \\n sequences into newlines", () => {
    const escaped = pem.replace(/\n/g, "\\n");
    assert.equal(resolvePem(escaped), pem);
  });

  it("wraps bare base64 certificate bodies as PEM", () => {
    const result = resolvePem(body, "cert") as string;
    assert.match(result, /^-----BEGIN CERTIFICATE-----\n/);
    assert.match(result, /-----END CERTIFICATE-----\n$/);
  });

  it("reads file paths for backwards compatibility", () => {
    const dir = mkdtempSync(join(tmpdir(), "saml-"));
    const file = join(dir, "key.pem");
    writeFileSync(file, pem);
    assert.equal((resolvePem(file) as Buffer).toString(), pem);
  });

  it("throws a helpful error for missing files", () => {
    assert.throws(
      () => resolvePem("./does-not-exist.pem"),
      /Could not read key\/certificate file/,
    );
  });
});

describe("SamlStrategy", () => {
  const validator = {
    validate: (_response: string) => Promise.resolve("skipped"),
  };

  const options = {
    validator,
    authURL: "http://localhost:3000",
    callbackURL: "http://localhost:3000/auth/saml/callback",
    idpMetadataURL: "http://localhost:7000/metadata",
    spAuthnRequestSigned: false,
    spWantAssertionSigned: false,
    spWantMessageSigned: false,
    spWantLogoutRequestSigned: false,
    spWantLogoutResponseSigned: false,
    spIsAssertionEncrypted: false,
  };

  it("should have the name of the strategy", () => {
    const strategy = new SamlStrategy(options, async () => null);
    assert.equal(strategy.name, "saml");
  });

  it("exposes SP metadata", () => {
    const strategy = new SamlStrategy(options, async () => null);
    const metadata = strategy.metadata();
    assert.match(metadata, /EntityDescriptor/);
    assert.match(metadata, /localhost:3000/);
  });
});
