import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as samlify from "samlify";
import {
  SamlStrategy,
  resolvePem,
  type SamlStrategyOptions,
} from "../src/index.ts";

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

describe("Single Logout", () => {
  const SP = "http://localhost:3000";
  const logoutURL = `${SP}/auth/saml/logout`;
  const REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
  const POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

  const idp = samlify.IdentityProvider({
    entityID: "http://localhost:7000/metadata",
    singleSignOnService: [
      { Binding: REDIRECT, Location: "http://localhost:7000/sso" },
    ],
    singleLogoutService: [
      { Binding: REDIRECT, Location: "http://localhost:7000/slo" },
      { Binding: POST, Location: "http://localhost:7000/slo" },
    ],
    wantLogoutRequestSigned: false,
    wantLogoutResponseSigned: false,
  });

  const baseOptions = {
    validator: { validate: (_xml: string) => Promise.resolve("skipped") },
    authURL: SP,
    callbackURL: `${SP}/auth/saml/callback`,
    idpMetadataURL: "http://localhost:7000/metadata",
    spAuthnRequestSigned: false,
    spWantAssertionSigned: false,
    spWantMessageSigned: false,
    spWantLogoutRequestSigned: false,
    spWantLogoutResponseSigned: false,
    spIsAssertionEncrypted: false,
    logoutURL,
  };

  const realFetch = globalThis.fetch;
  before(() => {
    globalThis.fetch = (async () =>
      new Response(idp.getMetadata())) as typeof fetch;
  });
  after(() => {
    globalThis.fetch = realFetch;
  });

  function setup(overrides: Partial<SamlStrategyOptions> = {}) {
    const calls: {
      nameID?: string;
      sessionIndex?: string;
      cookie: string | null;
    }[] = [];
    const strategy = new SamlStrategy(
      {
        ...baseOptions,
        onLogout: ({ nameID, sessionIndex, request }) => {
          calls.push({
            nameID,
            sessionIndex,
            cookie: request.headers.get("Cookie"),
          });
          return { headers: { "Set-Cookie": "session=; Max-Age=0" } };
        },
        ...overrides,
      },
      async () => null,
    );
    // Same SP as the strategy, as the IdP would know it from metadata.
    const sp = samlify.ServiceProvider({ metadata: strategy.metadata() });
    return { strategy, sp, calls };
  }

  const user = { logoutNameID: "user@example.com", sessionIndex: "_session1" };

  it("advertises the SLO endpoint in SP metadata", () => {
    const { strategy } = setup();
    assert.match(strategy.metadata(), /SingleLogoutService/);
    assert.match(strategy.metadata(), /auth\/saml\/logout/);
  });

  it("omits SLO from metadata when logoutURL is not set", () => {
    const { strategy } = setup({ logoutURL: undefined });
    assert.doesNotMatch(strategy.metadata(), /SingleLogoutService/);
  });

  it("builds an SP-initiated logout URL pointing at the IdP", async () => {
    const { strategy } = setup();
    const url = new URL(
      await strategy.getLogoutURL(
        { nameID: user.logoutNameID, sessionIndex: user.sessionIndex },
        { relayState: "/bye" },
      ),
    );
    assert.equal(url.origin + url.pathname, "http://localhost:7000/slo");
    assert.ok(url.searchParams.has("SAMLRequest"));
    assert.equal(url.searchParams.get("RelayState"), "/bye");
  });

  it("handles an IdP-initiated logout over HTTP-Redirect", async () => {
    const { strategy, sp, calls } = setup();
    const { context } = idp.createLogoutRequest(sp, "redirect", user, "/after");
    const request = new Request(`${logoutURL}${new URL(context).search}`, {
      headers: { Cookie: "session=abc" },
    });

    const response = await strategy.handleLogout(request);

    assert.deepEqual(calls, [
      {
        nameID: "user@example.com",
        sessionIndex: "_session1",
        cookie: "session=abc",
      },
    ]);
    assert.equal(response.status, 302);
    const location = new URL(response.headers.get("Location")!);
    assert.equal(
      location.origin + location.pathname,
      "http://localhost:7000/slo",
    );
    assert.ok(location.searchParams.has("SAMLResponse"));
    assert.equal(location.searchParams.get("RelayState"), "/after");
    assert.equal(response.headers.get("Set-Cookie"), "session=; Max-Age=0");
  });

  it("handles an IdP-initiated logout over HTTP-POST", async () => {
    const { strategy, sp, calls } = setup();
    const { context } = idp.createLogoutRequest(sp, "post", user) as {
      context: string;
    };
    const response = await strategy.handleLogout(
      new Request(logoutURL, {
        method: "POST",
        body: new URLSearchParams({ SAMLRequest: context, RelayState: "/x" }),
      }),
    );

    assert.equal(calls.length, 1);
    assert.equal(calls[0].nameID, "user@example.com");
    assert.equal(response.status, 200);
    assert.match(response.headers.get("Content-Type")!, /text\/html/);
    assert.equal(response.headers.get("Set-Cookie"), "session=; Max-Age=0");
    const html = await response.text();
    assert.match(html, /action="http:\/\/localhost:7000\/slo"/);
    assert.match(html, /name="SAMLResponse"/);
    assert.match(html, /name="RelayState" value="\/x"/);
  });

  it("completes an SP-initiated logout from the IdP's LogoutResponse", async () => {
    const { strategy, sp } = setup();
    const { context } = idp.createLogoutResponse(
      sp,
      { extract: { request: { id: "_abc" } } } as never,
      "redirect",
      "/goodbye",
    );
    const response = await strategy.handleLogout(
      new Request(`${logoutURL}${new URL(context).search}`),
      { headers: { "Set-Cookie": "session=; Max-Age=0" } },
    );
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("Location"), "/goodbye");
    assert.equal(response.headers.get("Set-Cookie"), "session=; Max-Age=0");
  });

  it("does not follow an off-site RelayState after logout", async () => {
    const { strategy, sp } = setup();
    const { context } = idp.createLogoutResponse(
      sp,
      { extract: { request: { id: "_abc" } } } as never,
      "redirect",
      "https://evil.example/phish",
    );
    const response = await strategy.handleLogout(
      new Request(`${logoutURL}${new URL(context).search}`),
      { redirectTo: "/home" },
    );
    assert.equal(response.headers.get("Location"), "/home");
  });

  it("rejects unsigned logout requests when signatures are required", async () => {
    const { strategy, sp, calls } = setup({ spWantLogoutRequestSigned: true });
    const { context } = idp.createLogoutRequest(sp, "redirect", user);
    const response = await strategy.handleLogout(
      new Request(`${logoutURL}${new URL(context).search}`),
    );
    assert.equal(response.status, 400);
    assert.equal(calls.length, 0);
  });

  describe("with signed messages", () => {
    const dir = mkdtempSync(join(tmpdir(), "saml-slo-"));
    const keyFile = join(dir, "idp.key");
    const certFile = join(dir, "idp.crt");
    let signedIdp: ReturnType<typeof samlify.IdentityProvider> | undefined;

    before(() => {
      try {
        execFileSync(
          "openssl",
          [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            keyFile,
            "-out",
            certFile,
            "-days",
            "2",
            "-subj",
            "/CN=idp.test",
          ],
          { stdio: "ignore" },
        );
      } catch {
        return; // openssl unavailable; tests below skip themselves
      }
      signedIdp = samlify.IdentityProvider({
        entityID: "http://localhost:7000/metadata",
        singleSignOnService: [
          { Binding: REDIRECT, Location: "http://localhost:7000/sso" },
        ],
        singleLogoutService: [
          { Binding: REDIRECT, Location: "http://localhost:7000/slo" },
        ],
        privateKey: readFileSync(keyFile),
        signingCert: readFileSync(certFile),
        wantLogoutRequestSigned: true,
        requestSignatureAlgorithm:
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      });
      globalThis.fetch = (async () =>
        new Response(signedIdp!.getMetadata())) as typeof fetch;
    });
    after(() => {
      globalThis.fetch = (async () =>
        new Response(idp.getMetadata())) as typeof fetch;
    });

    it("accepts a correctly signed redirect LogoutRequest and rejects a tampered one", async (t) => {
      if (!signedIdp) return t.skip("openssl not available");
      const { strategy, sp, calls } = setup({
        spWantLogoutRequestSigned: true,
      });
      const signingSp = samlify.ServiceProvider({
        metadata: strategy.metadata(),
        wantLogoutRequestSigned: true,
      });
      const { context } = signedIdp.createLogoutRequest(
        signingSp,
        "redirect",
        user,
        "/after",
      );
      assert.match(context, /Signature=/);

      const ok = await strategy.handleLogout(
        new Request(`${logoutURL}${new URL(context).search}`),
      );
      assert.equal(ok.status, 302, await ok.clone().text());
      assert.equal(calls.length, 1);

      const tampered = context.replace(
        "RelayState=%2Fafter",
        "RelayState=%2Fevil",
      );
      assert.notEqual(tampered, context);
      const bad = await strategy.handleLogout(
        new Request(`${logoutURL}${new URL(tampered).search}`),
      );
      assert.equal(bad.status, 400);
      assert.equal(calls.length, 1);
      void sp;
    });
  });

  it("returns 400 when there is no SAML message", async () => {
    const { strategy } = setup();
    const response = await strategy.handleLogout(new Request(logoutURL));
    assert.equal(response.status, 400);
  });

  it("returns 400 for garbage SAML", async () => {
    const { strategy, calls } = setup();
    const response = await strategy.handleLogout(
      new Request(logoutURL, {
        method: "POST",
        body: new URLSearchParams({ SAMLRequest: "bm90LXhtbA==" }),
      }),
    );
    assert.equal(response.status, 400);
    assert.equal(calls.length, 0);
  });
});
