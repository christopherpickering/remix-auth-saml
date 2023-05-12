import { redirect, SessionStorage } from "@remix-run/server-runtime";

import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";
import createDebug from "debug";
import invariant from "tiny-invariant";
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
 *
 * @example
 * let samlStrategy = new SamlStrategy({ validator }, async ({ extract, data}) => {
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
  constructor(
    options: SamlStrategyOptions,
    verify: StrategyVerifyCallback<User, SamlStrategyVerifyParams>
  ) {
    super(verify);
    invariant(process.env.AUTH_CALLBACK_URL, "AUTH_CALLBACK_URL must be set.");
    invariant(process.env.AUTH_URL, "AUTH_URL must be set.");
    this.callbackURL = process.env.AUTH_CALLBACK_URL;
    this.authURL = process.env.AUTH_URL;

    samlify.setSchemaValidator(options.validator);

    this.spData = {
      entityID: this.authURL,
      authnRequestsSigned:
        (process.env.SAML_SP_AUTHNREQUESTSSIGNED || "").toLowerCase() ===
        "true",
      wantAssertionsSigned:
        (process.env.SAML_SP_WANTASSERTIONSIGNED || "").toLowerCase() ===
        "true",
      wantMessageSigned:
        (process.env.SAML_SP_WANTMESSAGESIGNED || "").toLowerCase() === "true",
      wantLogoutResponseSigned:
        (process.env.SAML_SP_WANTLOGOUTREQUESTSIGNED || "").toLowerCase() ===
        "true",
      wantLogoutRequestSigned:
        (process.env.SAML_SP_WANTLOGOUTRESPONSESIGNED || "").toLowerCase() ===
        "true",
      isAssertionEncrypted:
        (process.env.SAML_SP_ISASSERTIONENCRYPTED || "").toLowerCase() ===
        "true",
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
      privateKey: process.env.SAML_PRIVATE_KEY
        ? fs.readFileSync(process.env.SAML_PRIVATE_KEY)
        : undefined,
      privateKeyPass: process.env.SAML_PRIVATE_KEY_PASS || undefined,
      encPrivateKey: process.env.SAML_ENC_PRIVATE_KEY
        ? fs.readFileSync(process.env.SAML_ENC_PRIVATE_KEY)
        : undefined,
    };
    this.sp = samlify.ServiceProvider(this.spData);
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    let url = new URL(request.url);
    let session = await sessionStorage.getSession(
      request.headers.get("Cookie")
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
          options
        );
      }

      user = await this.verify({
        extract,
        data: body,
      });

      debug("User authenticated");

      return await this.success(user, request, sessionStorage, options);
    } catch (error) {
      debug("Failed to login user", error);
      if (error instanceof Error) {
        return await this.failure(
          error.message,
          request,
          sessionStorage,
          options,
          error
        );
      }
      if (typeof error === "string") {
        return await this.failure(
          error,
          request,
          sessionStorage,
          options,
          new Error(error)
        );
      }
      return await this.failure(
        "Unknown error",
        request,
        sessionStorage,
        options,
        new Error(JSON.stringify(error, null, 2))
      );
    }
  }

  private async getAuthorizationURL(request: Request) {
    const idp = await this.getIdp();
    const { context } = this.sp.createLoginRequest(idp, "redirect");

    let params = new URLSearchParams(
      this.authorizationParams(new URL(context).searchParams)
    );

    params.set(
      "RelayState",
      this.getCallbackURL(new URL(request.url)).toString()
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
    invariant(process.env.SAML_IDP_METADATA, "SAML_IDP_METADATA must be set");
    const IpdXmlFetch = await fetch(process.env.SAML_IDP_METADATA);
    const Idpxml = await IpdXmlFetch.text();

    const idpData: IdentityProviderSettings = {
      metadata: Idpxml,
    };

    if (process.env.SAML_PRIVATE_KEY)
      idpData.privateKey = fs.readFileSync(process.env.SAML_PRIVATE_KEY);

    return samlify.IdentityProvider(idpData);
  }

  public metadata() {
    return this.sp.getMetadata();
  }
}
