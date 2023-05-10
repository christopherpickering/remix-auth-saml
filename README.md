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

Add environment variables.

```env
# your app url
AUTH_URL=http://localhost:3000
# callback url from the idp

AUTH_CALLBACK_URL=http://localhost:3000/auth/saml/callback

# your ipd metadata url
SAML_IDP_METADAT=http:localhost:7000/metadata

# remaining files are optional
SAML_SP_AUTHNREQUESTSSIGNED=false
SAML_SP_WANTASSERTIONSIGNED=false
SAML_SP_WANTMESSAGESIGNED=false
SAML_SP_WANTLOGOUTREQUESTSIGNED=false
SAML_SP_WANTLOGOUTRESPONSESIGNED=false
SAML_SP_ISASSERTIONENCRYPTED=false
SAML_PRIVATE_KEY="./test/saml-idp/idp-private-key.pem"
SAML_PRIVATE_KEY_PASS=""
SAML_ENC_PRIVATE_KEY="./test/saml-idp/idp-private-key.pem"
```

## Setup

Install a validator as specified in the samlify readme https://github.com/tngan/samlify/tree/master

### `services/auth.server.ts`

```ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { SamlStrategy } from "@/lib/SamlAuthStrategy";

// install and import an xml validator as directed here: https://github.com/tngan/samlify/tree/master
import * as validator from "@authenio/samlify-node-xmllint";

export let authenticator = new Authenticator<any>(sessionStorage);

let samlStrategy = new SamlStrategy({ validator }, async ({ profile }) => {
  console.log(profile);
  return true;
});

export let metadata = samlStrategy.metadata();

authenticator.use(samlStrategy);
```

### `routes/auth.saml.tsx`

The current url is saved to a cookie when a user accesses a protected page without being logged in.
They will run through the saml process and then be redirected to the same page.

See https://sergiodxa.com/articles/add-returnto-behavior-to-remix-auth for more information about how this works.

```ts
import type { ActionArgs, LoaderArgs } from "@remix-run/node";
import { redirect } from "@remix-run/node";
import { authenticator } from "~/services/auth.server";
import { returnToCookie } from "~/services/cookies.server";

export let action: ActionFunction = ({ request }) => login(request);
export let loader: LoaderFunction = ({ request }) => login(request);

async function login(request: Request) {
  let url = new URL(request.url);
  let returnTo = url.searchParams.get("returnTo") as string | null;

  try {
    return await authenticator.authenticate("saml", request, {
      successRedirect: returnTo ?? "/",
      failureRedirect: "/unauthorized",
    });
  } catch (error) {
    if (!returnTo) throw error;
    if (error instanceof Response && isRedirect(error)) {
      error.headers.append(
        "Set-Cookie",
        await returnToCookie.serialize(returnTo)
      );
      return error;
    }
    throw error;
  }
  return authenticator.authenticate("saml", request);
}

function isRedirect(response: Response) {
  if (response.status < 300 || response.status >= 400) return false;
  return response.headers.has("Location");
}
```

### Usage in protected routes

```ts
import { authenticator } from "~/services/auth.server";
import { json } from "@remix-run/node";
import type { LoaderArgs } from "@remix-run/node";

export async function loader({ request }: LoaderArgs) {
  // to redirect to login if not authed
  let user = await authenticator.isAuthenticated(request, {
    failureRedirect: `/auth/saml/?returnTo=${encodeURI(request.url)}`,
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
