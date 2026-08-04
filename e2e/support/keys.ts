/**
 * The signing key the asymmetric stub client authenticates with.
 *
 * Fixed rather than generated per run, because the public half is registered by
 * `scripts/seedStack.mjs` and the private half signs the assertion here. A
 * generated pair would have to be handed from the seed to the suite, which means
 * either a shared file written at run time or the seed becoming part of the
 * suite - both of which trade a readable fixture for machinery.
 *
 * This is a test credential for a stack whose administrator password is
 * "correct horse battery staple". It authenticates a stub client on a throwaway
 * endpoint and is worth nothing anywhere else.
 *
 * Author: John Grimes
 */

/** The `kid` in both halves of the pair, and in the assertion header. */
export const ASYMMETRIC_KID = "stub-asymmetric-1";

/** The private JWK, for signing a `private_key_jwt` client assertion. */
export const ASYMMETRIC_PRIVATE_JWK = {
  kty: "EC",
  crv: "P-384",
  x: "Nu9Nk903rbfzH-6LCN_8clmcRHFRfub-o6mepu51nEaafbnS0ZmjlzWCQYSk2c4m",
  y: "2Je25QiKuJGBGAoeNZXU5Ax-qrXbLDYMXgAkTTOOM3zqCtD98J2JEScC7UufEcNz",
  d: "xSo5YaP9L0XsKKuotMkRUFiehSyv2KluPb1a7En5--acN4CwXuErhWzbMMhWSAqM",
  alg: "ES384",
  kid: ASYMMETRIC_KID,
} as const;
