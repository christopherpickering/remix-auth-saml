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

let samlStrategy = new SamlStrategy(
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
    // Prefer PEM string / Buffer (required on Cloudflare):
    // privateKey: process.env.SAML_PRIVATE_KEY,
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
