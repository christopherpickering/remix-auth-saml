# Remix Auth Saml Strategy Template

Use this strategy to add SAML single sign on to your remix site.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## Install

Install the package.

```bash
npm i remix-auth-saml
```

## Setup

Install a validator as specified in the samlify readme https://github.com/tngan/samlify/tree/master

### `services/auth.server.ts`

```ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { SamlStrategy } from "remix-auth-saml";

// install and import an xml validator as directed here: https://github.com/tngan/samlify/tree/master
import * as validator from "@authenio/samlify-node-xmllint";

export let authenticator = new Authenticator<any>(sessionStorage);

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
    // optional
    privateKey: "./test/saml-idp/idp-private-key.pem",
    // optional
    privateKeyPass: "",
    // optional
    encPrivateKey: "./test/saml-idp/idp-private-key.pem",
    // optional
    privateKey: "./test/saml-idp/idp-private-key.pem",
    // optional
    signingCert: "./test/saml-idp/idp-private-key.crt",
    // optional
    encryptCert: "./test/saml-idp/idp-private-key.crt",
  },
  async ({ extract, data }) => {
    console.log("profile", extract);
    // data is the raw response from the idp
    // this could be passed into a backend for decryption
    // if you need to verify authentication in the backend.
    // if remix is the backend, the you can use the
    // extract directly
    console.log("data", data);
    return false;
  }
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
    // if relay state was set we can redirect to it.
    const newRequest = request.clone();
    const formData = await newRequest.formData();
    const body = Object.fromEntries(formData);
    successRedirect = (formData.get("RelayState") || "/").toString();
  } catch (e) {}

  // call authenticate to complete the login and set returnTo as the successRedirect
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
  // to redirect to login if not authed
  // The current url can be passed passed to the ipd as a RelayState when
  // a user accesses a protected page without being logged in.
  // They will run through the saml process and then be redirected to
  // the same page.

  let user = await authenticator.isAuthenticated(request, {
    failureRedirect: `/auth/saml/?returnTo=${encodeURI(request.url)}`,

    // or to go back to the root `/`
    //failureRedirect: "/auth/saml/",
  });
  return json({ user });
}

export default function Login() {
  return <>protected page!</>;
}
```

### Access SP Metadata `routes/metadata[.]xml.tsx`

You may need access to the `sp` metadata to keep in sync with your `ipd` automatically.

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
