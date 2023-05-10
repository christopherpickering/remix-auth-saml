import { installGlobals } from "@remix-run/node";
import "jest-fetch-mock/setupJest";

// installGlobals();
process.env.AUTH_CALLBACK_URL = "http:localhost:3000/callback";
process.env.AUTH_URL = "http:localhost:3000";
