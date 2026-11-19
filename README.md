# Remix Auth Saml Strategy

SAML single sign-on strategy for [Remix Auth](https://github.com/sergiodxa/remix-auth), powered by [samlify](https://github.com/tngan/samlify).

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅\*        |

\*Pass PEM contents or `Buffer`s for keys/certs. File paths only work on Node.

## Install

```bash
npm i remix-auth-saml
```

Also install peer deps if needed: `remix-auth`, `@remix-run/server-runtime`.

## Setup

Install a validator as specified in the [samlify readme](https://github.com/tngan/samlify/tree/master).

### `services/auth.server.ts`

```ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { SamlStrategy } from "remix-auth-saml";
import * as validator from "@authenio/samlify-node-xmllint";
// Node: import { readFileSync } from "node:fs";

export let authenticator = new Authenticator(sessionStorage);

export let samlStrategy = new SamlStrategy(
  {
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
    // Prefer PEM string / Buffer (required on Cloudflare, works with
    // Secrets Manager / env vars; literal "\n" sequences are supported and
    // bare base64 cert bodies are accepted for signingCert/encryptCert):
    // privateKey: process.env.SAML_PRIVATE_KEY,
    // signingCert: await getSecret("saml-signing-cert"),
    // Or a Node filesystem path (still supported):
    // privateKey: "./certs/sp-private-key.pem",
  },
  async ({ extract, data }) => {
    // `extract` is the parsed assertion; `data` is the raw IdP POST body
    return { id: extract.nameID };
  },
);

export let metadata = samlStrategy.metadata();

authenticator.use(samlStrategy);
```

### `routes/auth.saml.tsx`

```ts
import type { ActionFunction, LoaderFunction } from "@remix-run/node";
import { authenticator } from "~/services/auth.server";

export let action: ActionFunction = ({ request }) => login(request);
export let loader: LoaderFunction = ({ request }) => login(request);

async function login(request: Request) {
  return authenticator.authenticate("saml", request);
}
```

### `routes/auth.saml.callback.tsx`

```ts
import type { ActionFunction, LoaderFunction } from "@remix-run/node";
import { authenticator } from "~/services/auth.server";

export let action: ActionFunction = ({ request }) => login(request);
export let loader: LoaderFunction = ({ request }) => login(request);

async function login(request: Request) {
  let successRedirect = "/";

  try {
    const formData = await request.clone().formData();
    successRedirect = (formData.get("RelayState") || "/").toString();
  } catch {}

  return authenticator.authenticate("saml", request, {
    successRedirect,
    failureRedirect: "/unauthenticated",
  });
}
```

### Usage in protected routes

```ts
import { authenticator } from "~/services/auth.server";
import { json } from "@remix-run/node";
import type { LoaderArgs } from "@remix-run/node";

export async function loader({ request }: LoaderArgs) {
  let user = await authenticator.isAuthenticated(request, {
    failureRedirect: `/auth/saml/?returnTo=${encodeURI(request.url)}`,
  });
  return json({ user });
}
```

### Single Logout (SLO)

Single Logout is opt-in. Both IdP-initiated (the IdP tells your app to log a
user out) and SP-initiated (your app starts the logout) flows are supported,
over the HTTP-Redirect and HTTP-POST bindings.

Because every app stores sessions differently, you provide an `onLogout`
callback that destroys the user's session. Add `logoutURL` and `onLogout` to
the strategy options in `services/auth.server.ts`:

```ts
let samlStrategy = new SamlStrategy(
  {
    // ...existing options
    logoutURL: "http://localhost:3000/auth/saml/logout", // advertised in SP metadata
    // Strongly recommended: reject unsigned logout requests, which anyone
    // could otherwise forge to log your users out.
    spWantLogoutRequestSigned: true,
    // IdP-initiated logout: destroy the user's session. `request` carries the
    // browser's cookies, so you can find the session from it.
    onLogout: async ({ nameID, sessionIndex, request }) => {
      let session = await sessionStorage.getSession(
        request.headers.get("Cookie"),
      );
      return {
        headers: { "Set-Cookie": await sessionStorage.destroySession(session) },
      };
    },
  },
  verify,
);
```

Register the logout URL with your IdP (it is included in the SP metadata) and
add a route that hands IdP messages to the strategy. This one route handles
both the IdP's LogoutRequests and the LogoutResponses to logouts you start:

```ts
// routes/auth.saml.logout.tsx
import type { ActionFunction, LoaderFunction } from "@remix-run/node";
import { samlStrategy } from "~/services/auth.server";

export let loader: LoaderFunction = ({ request }) =>
  samlStrategy.handleLogout(request, { redirectTo: "/" });
export let action: ActionFunction = ({ request }) =>
  samlStrategy.handleLogout(request, { redirectTo: "/" });
```

To start a logout from your app (SP-initiated), keep the login `nameID` and
`sessionIndex` in the user you return from `verify`
(`extract.nameID`, `extract.sessionIndex?.sessionIndex`), then redirect to the
IdP while destroying the local session:

```ts
// routes/logout.tsx
import { redirect } from "@remix-run/node";
import { samlStrategy } from "~/services/auth.server";
import { sessionStorage } from "~/services/session.server";

export async function action({ request }) {
  let session = await sessionStorage.getSession(request.headers.get("Cookie"));
  let user = session.get("user");
  return redirect(
    await samlStrategy.getLogoutURL({
      nameID: user.nameID,
      sessionIndex: user.sessionIndex,
    }),
    { headers: { "Set-Cookie": await sessionStorage.destroySession(session) } },
  );
}
```

`handleLogout` verifies the message (including its signature when
`spWantLogoutRequestSigned` / `spWantLogoutResponseSigned` is set) and returns a
`Response`: a redirect or auto-submitting form back to the IdP for an
IdP-initiated logout, and a redirect to a same-origin `RelayState` (or
`redirectTo`) when your own logout completes. Invalid messages get a `400`.

### Access SP Metadata `routes/metadata[.]xml.tsx`

```ts
import { metadata } from "~/services/auth.server";

export const loader = async () => {
  return new Response(metadata, {
    status: 200,
    headers: {
      "Content-Type": "text/xml",
    },
  });
};
```
