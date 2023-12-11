import { redirect, SessionStorage } from "@remix-run/server-runtime";

import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";
import createDebug from "debug";

import fs from "fs";
import * as samlify from "samlify";
import type {
  IdentityProviderSettings,
  ServiceProviderSettings,
} from "samlify/types/src/types";

import type { ServiceProvider } from "samlify/types/src/entity-sp";

let debug = createDebug("SamlStrategy");

interface ValidatorContext {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  validate?: (xml: string) => Promise<any>;
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
  privateKey?: string;
  privateKeyPass?: string;
  encPrivateKey?: string;
  signingCert?: string;
  encryptCert?: string;
}

export interface SamlStrategyVerifyParams {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  extract: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any;
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
 * - `spAuthnRequestSigned`
 * - `spWantAssertionSigned`
 * - `spWantMessageSigned`
 * - `spWantLogoutRequestSigned`
 * - `spWantLogoutResponseSigned`
 * - `spIsAssertionEncrypted`
 * - `privateKey` Optional path to private key.
 * - `privateKeyPass` Optional private key password.
 * - `encPrivateKey` Optional path to encrypted private key.
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
  protected privateKey?: string;

  constructor(
    options: SamlStrategyOptions,
    verify: StrategyVerifyCallback<User, SamlStrategyVerifyParams>,
  ) {
    super(verify);
    this.callbackURL = options.callbackURL;
    this.authURL = options.authURL;
    this.idpMetadataURL = options.idpMetadataURL;
    this.privateKey = options.privateKey;
    samlify.setSchemaValidator(options.validator);

    this.spData = {
      entityID: this.authURL,
      authnRequestsSigned: options.spAuthnRequestSigned,
      wantAssertionsSigned: options.spWantAssertionSigned,
      wantMessageSigned: options.spWantMessageSigned,
      wantLogoutResponseSigned: options.spWantLogoutRequestSigned,
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
      // singleLogoutService: [
      //   {
      //     Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      //     Location: this.authURL + "/auth/slo",
      //   },
      //   {
      //     Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
      //     Location: this.authURL + "/auth/slo",
      //   },
      // ],
      privateKey: options.privateKey
        ? fs.readFileSync(options.privateKey)
        : undefined,
      privateKeyPass: options.privateKeyPass,
      encPrivateKey: options.encPrivateKey
        ? fs.readFileSync(options.encPrivateKey)
        : undefined,
      signingCert: options.signingCert
        ? fs.readFileSync(options.signingCert)
        : undefined,
      encryptCert: options.encryptCert
        ? fs.readFileSync(options.encryptCert)
        : undefined,
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

    // User is already authenticated
    if (user) {
      debug("User is authenticated");
      return this.success(user, request, sessionStorage, options);
    }

    let callbackURL = this.getCallbackURL(url);
    debug("Callback URL", callbackURL);

    if (url.pathname !== callbackURL.pathname) {
      debug("Redirecting to ipd login URL");
      const authURL = await this.getAuthorizationURL(request);
      throw redirect(authURL.toString(), {
        headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
      });
    }

    debug("Callback from ipd");
    try {
      const formData = await request.formData();
      const body = Object.fromEntries(formData);
      const idp = await this.getIdp();
      const { extract } = await this.sp.parseLoginResponse(idp, "post", {
        body,
      });
      if (!extract.nameID) {
        debug("Failed to login.");
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
      debug("Failed to login user", error);
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

    debug("User authenticated");

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

    if (this.privateKey) idpData.privateKey = fs.readFileSync(this.privateKey);

    return samlify.IdentityProvider(idpData);
  }

  public metadata() {
    return this.sp.getMetadata();
  }
}
