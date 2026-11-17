import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { SamlStrategy } from "../src/index.ts";

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
