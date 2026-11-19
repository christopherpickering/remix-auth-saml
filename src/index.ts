import { redirect, SessionStorage } from "@remix-run/server-runtime";

import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";

import * as samlify from "samlify";
import type {
  ESamlHttpRequest,
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
  /**
   * Absolute URL of this app's Single Logout Service route (the route that
   * calls `strategy.handleLogout(request)`). Setting it advertises the SLO
   * endpoint in the SP metadata, which Single Logout requires.
   */
  logoutURL?: string;
  /**
   * Called when the IdP asks to log a user out (IdP-initiated logout). Destroy
   * the user's local session here. The `request` is the browser's request, so
   * its cookies can be used to locate the session. Return `headers` (e.g. a
   * `Set-Cookie` from `sessionStorage.destroySession`) to attach them to the
   * response sent back to the IdP.
   */
  onLogout?: (
    params: SamlLogoutParams,
  ) => Promise<SamlLogoutResult | void> | SamlLogoutResult | void;
}

export interface SamlStrategyVerifyParams {
  extract: { nameID?: string; [key: string]: unknown };
  data: Record<string, FormDataEntryValue>;
}

export interface SamlLogoutParams {
  /** NameID of the user the IdP wants logged out. */
  nameID?: string;
  /** SessionIndex the IdP wants logged out, if it sent one. */
  sessionIndex?: string;
  /** The incoming logout request. */
  request: Request;
}

export interface SamlLogoutResult {
  /** Extra headers for the response (e.g. `Set-Cookie` to clear the session). */
  headers?: HeadersInit;
}

export interface SamlHandleLogoutOptions {
  /**
   * Where to send the browser once an SP-initiated logout completes and the
   * IdP's `RelayState` is missing or not same-origin. Defaults to `/`.
   */
  redirectTo?: string;
  /**
   * Extra headers for the redirect sent when an SP-initiated logout completes
   * (e.g. a `Set-Cookie` that destroys the session).
   */
  headers?: HeadersInit;
}

export interface SamlLogoutUser {
  /** The `nameID` from the login `extract`. */
  nameID: string;
  /** The `sessionIndex` from the login `extract`, if the IdP sent one. */
  sessionIndex?: string;
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
 * Splits a query string into what samlify's redirect binding needs: decoded
 * `query` values (as Express provides them) and the `octetString` that was
 * signed, which must be the exact bytes as sent, so it can't be rebuilt from
 * `URLSearchParams`.
 */
function parseRawQuery(search: string, direction: string) {
  const query: Record<string, string> = {};
  const raw: Record<string, string> = {};
  for (const part of search.replace(/^\?/, "").split("&")) {
    if (!part) continue;
    const index = part.indexOf("=");
    const key = decodeURIComponent(index < 0 ? part : part.slice(0, index));
    raw[key] = index < 0 ? "" : part.slice(index + 1);
    query[key] = decodeURIComponent(raw[key]);
  }
  // saml-bindings 3.4.4.1: the signed octets are the message, RelayState and
  // SigAlg, in that order, exactly as sent.
  const octetString = [direction, "RelayState", "SigAlg"]
    .filter((key) => key in raw)
    .map((key) => `${key}=${raw[key]}`)
    .join("&");
  return { query, octetString };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function autoSubmitForm(
  endpoint: string,
  fields: Record<string, string>,
  headers?: HeadersInit,
): Response {
  const inputs = Object.entries(fields)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`,
    )
    .join("");
  const html = `<!DOCTYPE html><html><body onload="document.forms[0].submit()"><form method="post" action="${escapeHtml(endpoint)}">${inputs}<noscript><button type="submit">Continue</button></noscript></form></body></html>`;
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "text/html; charset=utf-8");
  responseHeaders.set("Cache-Control", "no-store");
  return new Response(html, { status: 200, headers: responseHeaders });
}

/** Only follow a RelayState that stays on this site (no open redirects). */
function safeRelayState(
  relayState: string | undefined,
  requestURL: URL,
  fallback: string,
): string {
  if (!relayState) return fallback;
  if (relayState.startsWith("/") && !/^\/[\\/]/.test(relayState)) {
    return relayState;
  }
  try {
    const target = new URL(relayState);
    if (target.origin === requestURL.origin) return target.toString();
  } catch {
    // not an absolute URL
  }
  return fallback;
}

function badRequest(message: string): Response {
  return new Response(message, {
    status: 400,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
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
 * - `logoutURL` + `onLogout` enable Single Logout; see `handleLogout` and
 *   `getLogoutURL`.
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
  protected logoutURL?: string;
  protected onLogout?: SamlStrategyOptions["onLogout"];
  protected privateKey?: string | Buffer;

  constructor(
    options: SamlStrategyOptions,
    verify: StrategyVerifyCallback<User, SamlStrategyVerifyParams>,
  ) {
    super(verify);
    this.callbackURL = options.callbackURL;
    this.authURL = options.authURL;
    this.idpMetadataURL = options.idpMetadataURL;
    this.logoutURL = options.logoutURL;
    this.onLogout = options.onLogout;
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
      ...(this.logoutURL
        ? {
            singleLogoutService: [
              {
                Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                Location: this.logoutURL,
              },
              {
                Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                Location: this.logoutURL,
              },
            ],
          }
        : {}),
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

  /**
   * SP-initiated logout, step 1: builds the URL that sends the user to the
   * IdP's Single Logout Service. Destroy the local session as you redirect,
   * e.g.
   *
   *   return redirect(await strategy.getLogoutURL({ nameID, sessionIndex }), {
   *     headers: { "Set-Cookie": await sessionStorage.destroySession(session) },
   *   });
   *
   * Store `nameID` (and `sessionIndex`, `extract.sessionIndex?.sessionIndex`)
   * from the login `extract` in the session so they're available here.
   * The IdP finishes by sending a LogoutResponse to `logoutURL`, which
   * `handleLogout` completes.
   */
  public async getLogoutURL(
    user: SamlLogoutUser,
    options: { relayState?: string } = {},
  ): Promise<string> {
    const idp = await this.getIdp();
    const { context } = this.sp.createLogoutRequest(
      idp,
      "redirect",
      { logoutNameID: user.nameID, sessionIndex: user.sessionIndex },
      options.relayState,
    );
    return context;
  }

  /**
   * Handles everything the IdP sends to `logoutURL`, for both bindings
   * (HTTP-Redirect via GET, HTTP-POST via POST). Use it in the loader and
   * action of the route at `logoutURL` and return its Response:
   *
   * - LogoutRequest (IdP-initiated): verified, handed to `onLogout` so the
   *   app can destroy the session, then answered with a LogoutResponse.
   * - LogoutResponse (SP-initiated, from `getLogoutURL`): verified, then the
   *   user is redirected to a same-origin RelayState or `options.redirectTo`.
   *
   * Set `spWantLogoutRequestSigned: true` so unsigned logout requests, which
   * anyone could forge to log users out, are rejected.
   */
  public async handleLogout(
    request: Request,
    options: SamlHandleLogoutOptions = {},
  ): Promise<Response> {
    const url = new URL(request.url);
    const isPost = request.method === "POST";
    const binding = isPost ? "post" : "redirect";

    let direction: "SAMLRequest" | "SAMLResponse";
    let samlRequest: ESamlHttpRequest;
    let relayState: string | undefined;
    try {
      if (isPost) {
        const formData = await request.formData();
        const body: Record<string, string> = {};
        formData.forEach((value, key) => {
          if (typeof value === "string") body[key] = value;
        });
        if (body.SAMLRequest !== undefined) direction = "SAMLRequest";
        else if (body.SAMLResponse !== undefined) direction = "SAMLResponse";
        else return badRequest("Missing SAMLRequest or SAMLResponse");
        samlRequest = { body };
        relayState = body.RelayState;
      } else {
        const params = url.searchParams;
        if (params.has("SAMLRequest")) direction = "SAMLRequest";
        else if (params.has("SAMLResponse")) direction = "SAMLResponse";
        else return badRequest("Missing SAMLRequest or SAMLResponse");
        const { query, octetString } = parseRawQuery(url.search, direction);
        samlRequest = { query, octetString };
        relayState = params.get("RelayState") ?? undefined;
      }
    } catch {
      return badRequest("Invalid SAML logout message");
    }

    const idp = await this.getIdp();

    if (direction === "SAMLResponse") {
      try {
        await this.sp.parseLogoutResponse(idp, binding, samlRequest);
      } catch (error) {
        return badRequest(
          error instanceof Error
            ? error.message
            : "Invalid SAML logout response",
        );
      }
      return redirect(
        safeRelayState(relayState, url, options.redirectTo ?? "/"),
        { headers: options.headers },
      );
    }

    let parsed;
    try {
      parsed = await this.sp.parseLogoutRequest(idp, binding, samlRequest);
    } catch (error) {
      return badRequest(
        error instanceof Error ? error.message : "Invalid SAML logout request",
      );
    }

    const { extract } = parsed;
    const result = await this.onLogout?.({
      nameID: typeof extract.nameID === "string" ? extract.nameID : undefined,
      sessionIndex:
        typeof extract.sessionIndex === "string"
          ? extract.sessionIndex
          : undefined,
      request,
    });

    const response = this.sp.createLogoutResponse(
      idp,
      { extract },
      binding,
      relayState,
    );

    if (binding === "redirect") {
      return redirect((response as { context: string }).context, {
        headers: result?.headers,
      });
    }
    const post = response as {
      context: string;
      entityEndpoint: string;
      relayState?: string;
    };
    const fields: Record<string, string> = { SAMLResponse: post.context };
    if (post.relayState) fields.RelayState = post.relayState;
    return autoSubmitForm(post.entityEndpoint, fields, result?.headers);
  }

  public metadata() {
    return this.sp.getMetadata();
  }
}
