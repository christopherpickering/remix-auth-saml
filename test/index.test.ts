import { createCookieSessionStorage } from "@remix-run/node";
import { SamlStrategy } from "../src";

describe(SamlStrategy, () => {
  let verify = jest.fn();
  // You will probably need a sessionStorage to test the strategy.
  let sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });

  beforeEach(() => {
    jest.resetAllMocks();
  });

  const validator = {
    validate: (response: string) => {
      return Promise.resolve("skipped");
    },
  };

  test("should have the name of the strategy", () => {
    let strategy = new SamlStrategy({ validator }, verify);
    expect(strategy.name).toBe("saml");
  });

  // test.todo("Write more tests to check everything works as expected");
});
