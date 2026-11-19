import { redirect, SessionStorage } from "@remix-run/server-runtime";

import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";

import * as samlify from "samlify";
import type {
  IdentityProviderSettings,
  ServiceProviderSettings,
} from "samlify/types/src/types";

import type { ServiceProvider } from "samlify/types/src/entity-sp";

/** PEM contents or a Node filesystem path (path support is Node-only). */
export type PemOrPath = string | Buffer;

interface ValidatorContext {
  validate?: (xml: string) => Promise<unknown>;
}

export interface SamlStrategyOptions {
  validator: ValidatorContext;
  authURL: string;
  callbackURL: string;
  idpMetadataURL: string;
  spAuthnRequestSigned: boolean;
  spWantAssertionSigned: boolean;
  spWantMessageSigned: boolean;
  spWantLogoutRequestSigned: boolean;
  spWantLogoutResponseSigned: boolean;
  spIsAssertionEncrypted: boolean;
  privateKey?: PemOrPath;
  privateKeyPass?: string;
  encPrivateKey?: PemOrPath;
  signingCert?: PemOrPath;
  encryptCert?: PemOrPath;
}

export interface SamlStrategyVerifyParams {
  extract: { nameID?: string; [key: string]: unknown };
  data: Record<string, FormDataEntryValue>;
}

function loadFs(): typeof import("node:fs") {
  // Loaded lazily so Cloudflare/edge bundles don't pull in `fs` when callers
  // pass PEM contents or Buffers instead of file paths.
  if (typeof require === "function") {
    return require("node:fs") as typeof import("node:fs");
  }
  const getBuiltin = (
    process as unknown as {
      getBuiltinModule?: (id: string) => unknown;
    }
  ).getBuiltinModule;
  const fs = getBuiltin?.("node:fs") as typeof import("node:fs") | undefined;
  if (!fs) {
    throw new Error(
      "Filesystem access is unavailable in this runtime; pass PEM contents (string or Buffer) instead of a file path.",
    );
  }
  return fs;
}

function wrapPem(base64: string, label: string): string {
  const body = base64.replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * Resolves a key/cert option to something samlify accepts.
 *
 * Accepted inputs, in order:
 * 1. `Buffer` - used as-is.
 * 2. PEM string (contains `-----BEGIN `) - used as-is. Literal `\n` sequences
 *    (common in env vars / secret stores) are converted to real newlines.
 * 3. Bare base64 certificate body (`kind: "cert"` only) - wrapped as PEM.
 * 4. Anything else - treated as a filesystem path (Node only).
 */
export function resolvePem(
  value?: PemOrPath,
  kind: "cert" | "key" = "key",
): string | Buffer | undefined {
  if (value == null) return undefined;
  if (typeof value !== "string") return value;

  const trimmed = value.trim();
  if (trimmed === "") return undefined;

  if (/-----BEGIN /.test(trimmed)) {
    return trimmed.includes("\\n") && !trimmed.includes("\n")
      ? trimmed.replace(/\\n/g, "\n")
      : trimmed;
  }

  if (kind === "cert" && /^[A-Za-z0-9+/=\s]{64,}$/.test(trimmed)) {
    return wrapPem(trimmed, "CERTIFICATE");
  }

  // Back-compat: treat plain strings as filesystem paths (Node only).
  try {
    return loadFs().readFileSync(trimmed);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
      throw new Error(
        `Could not read key/certificate file "${trimmed}". Pass PEM contents (string or Buffer) or a valid file path.`,
      );
    }
    throw error;
  }
}

/**
 * The SAML authentication strategy authenticates requests using SAML2.0.
 *
 * Application must specify a `verify` callback:
 *
 *   function({profile, body}) { ... }
 *
 * Options:
 * - `validator` Validator installed following samlify's guide.
 * - `authURL` Websites base url.
 * - `callbackURL` Authentication callback url.
 * - `idpMetadataURL` URL for IDP Metadata xml file.
 * - Key/cert options accept PEM string, Buffer, or (Node only) a file path.
 *
 * @example
 * let samlStrategy = new SamlStrategy(options, async ({ extract, data}) => {
 *   console.log("profile", extract);
 *   // data is the raw response from the idp
 *   // this could be passed into a backend for decryption
 *   // if you need to verify authentication in the backend.
 *   // if remix is the backend, the you can use the
 *   // extract directly
 *   console.log("data", data);
 *   return true;
 * });
 * // sp metadata is accessible.
 * export let metadata = samlStrategy.metadata();
 *
 * authenticator.use(samlStrategy)
 */
export class SamlStrategy<User> extends Strategy<
  User,
  SamlStrategyVerifyParams
> {
  name = "saml";

  protected callbackURL: string;
  protected authURL: string;
  protected spData: ServiceProviderSettings;
  protected sp: ServiceProvider;
  protected idpMetadataURL: string;
  protected privateKey?: string | Buffer;

  constructor(
    options: SamlStrategyOptions,
    verify: StrategyVerifyCallback<User, SamlStrategyVerifyParams>,
  ) {
    super(verify);
    this.callbackURL = options.callbackURL;
    this.authURL = options.authURL;
    this.idpMetadataURL = options.idpMetadataURL;
    // Resolve once so file paths aren't re-read on every request.
    this.privateKey = resolvePem(options.privateKey, "key");
    samlify.setSchemaValidator(options.validator);

    this.spData = {
      entityID: this.authURL,
      authnRequestsSigned: options.spAuthnRequestSigned,
      wantAssertionsSigned: options.spWantAssertionSigned,
      wantMessageSigned: options.spWantMessageSigned,
      wantLogoutResponseSigned: options.spWantLogoutResponseSigned,
      wantLogoutRequestSigned: options.spWantLogoutRequestSigned,
      isAssertionEncrypted: options.spIsAssertionEncrypted,
      assertionConsumerService: [
        {
          Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Location: this.callbackURL,
        },
        {
          Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          Location: this.callbackURL,
        },
      ],
      privateKey: this.privateKey,
      privateKeyPass: options.privateKeyPass,
      encPrivateKey: resolvePem(options.encPrivateKey, "key"),
      signingCert: resolvePem(options.signingCert, "cert"),
      encryptCert: resolvePem(options.encryptCert, "cert"),
    };
    this.sp = samlify.ServiceProvider(this.spData);
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
  ): Promise<User> {
    let url = new URL(request.url);
    let session = await sessionStorage.getSession(
      request.headers.get("Cookie"),
    );

    let user: User | null = session.get(options.sessionKey) ?? null;

    if (user) {
      return this.success(user, request, sessionStorage, options);
    }

    let callbackURL = this.getCallbackURL(url);

    if (url.pathname !== callbackURL.pathname) {
      const authURL = await this.getAuthorizationURL(request);
      throw redirect(authURL.toString(), {
        headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
      });
    }

    try {
      const formData = await request.formData();
      const body = Object.fromEntries(formData);
      const idp = await this.getIdp();
      const { extract } = await this.sp.parseLoginResponse(idp, "post", {
        body,
      });
      if (!extract.nameID) {
        return await this.failure(
          "Failed to login",
          request,
          sessionStorage,
          options,
        );
      }

      user = await this.verify({
        extract,
        data: body,
      });
    } catch (error) {
      if (error instanceof Error) {
        return await this.failure(
          error.message,
          request,
          sessionStorage,
          options,
          error,
        );
      }
      if (typeof error === "string") {
        return await this.failure(
          error,
          request,
          sessionStorage,
          options,
          new Error(error),
        );
      }
      return await this.failure(
        "Unknown error",
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2)),
      );
    }

    return await this.success(user, request, sessionStorage, options);
  }

  private async getAuthorizationURL(request: Request) {
    const idp = await this.getIdp();
    const { context } = this.sp.createLoginRequest(idp, "redirect");

    let params = new URLSearchParams(
      this.authorizationParams(new URL(context).searchParams),
    );

    let requestParams = new URLSearchParams(
      this.authorizationParams(new URL(request.url).searchParams),
    );

    params.set(
      "RelayState",
      requestParams.get("returnTo") ||
        requestParams.get("relayState") ||
        requestParams.get("redirect_url") ||
        this.getCallbackURL(new URL(request.url)).toString(),
    );

    let url = new URL(context);
    url.search = params.toString();
    return url;
  }

  protected authorizationParams(params: URLSearchParams): URLSearchParams {
    return new URLSearchParams(params);
  }

  private getCallbackURL(url: URL) {
    if (
      this.callbackURL.startsWith("http:") ||
      this.callbackURL.startsWith("https:")
    ) {
      return new URL(this.callbackURL);
    }
    if (this.callbackURL.startsWith("/")) {
      return new URL(this.callbackURL, url);
    }
    return new URL(`${url.protocol}//${this.callbackURL}`);
  }

  private async getIdp() {
    const IpdXmlFetch = await fetch(this.idpMetadataURL);
    const Idpxml = await IpdXmlFetch.text();

    const idpData: IdentityProviderSettings = {
      metadata: Idpxml,
    };

    if (this.privateKey) idpData.privateKey = this.privateKey;

    return samlify.IdentityProvider(idpData);
  }

  public metadata() {
    return this.sp.getMetadata();
  }
}
