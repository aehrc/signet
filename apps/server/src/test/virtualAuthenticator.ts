/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A software authenticator, for driving the passkey routes without a browser.
 *
 * The alternative was stubbing `@simplewebauthn/server` in the integration suite,
 * and that would have hollowed the tests out: almost everything worth asserting
 * about these routes - that a replayed challenge is refused, that a counter which
 * did not advance is refused, that a ceremony for another origin does not verify -
 * is a property of the verification the stub would have replaced. So this produces
 * genuine ceremony responses instead, signed with a real P-256 key, and the server
 * under test runs its real verifier over them.
 *
 * It implements only what a passkey needs and nothing else: ES256, `none`
 * attestation, and the flags a user-verifying platform authenticator sets. It is not
 * a WebAuthn client - it does not choose credentials, enforce `excludeCredentials`
 * or check the RP ID, because those are the browser's jobs and the browser is what
 * the end-to-end suite exercises with Chromium's own virtual authenticator.
 *
 * Author: John Grimes
 */

import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";

import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

/** WebAuthn's user-present flag. */
const FLAG_USER_PRESENT = 0x01;

/** WebAuthn's user-verified flag - the one that stands in for a second factor. */
const FLAG_USER_VERIFIED = 0x04;

/** WebAuthn's attested-credential-data flag, set only during registration. */
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

/** COSE key type EC2. */
const COSE_KTY_EC2 = 2;

/** COSE algorithm ES256. */
const COSE_ALG_ES256 = -7;

/** COSE curve P-256. */
const COSE_CRV_P256 = 1;

/** How the authenticator identifies its make and model. Zeroes: none claimed. */
const AAGUID = new Uint8Array(16);

/** What a ceremony should report, when a test wants something other than the usual. */
export interface CeremonyOptions {
  /**
   * Whether the authenticator claims to have verified its user.
   *
   * False produces the ceremony Signet must refuse: a passkey only replaces the
   * second factor because the authenticator checked who was holding it.
   */
  readonly userVerified?: boolean;
  /** The signature counter to report, overriding the authenticator's own. */
  readonly counter?: number;
  /** The origin to claim in `clientDataJSON`, for the phishing-resistance case. */
  readonly origin?: string;
}

/** One software authenticator, holding one credential once it has registered. */
export interface VirtualAuthenticator {
  /** The credential's base64url identifier, as the browser would report it. */
  readonly credentialId: string;
  /** Produces a registration response for the given creation options. */
  readonly register: (
    options: PublicKeyCredentialCreationOptionsJSON,
    ceremony?: CeremonyOptions,
  ) => Promise<RegistrationResponseJSON>;
  /** Produces an assertion for the given request options. */
  readonly authenticate: (
    options: PublicKeyCredentialRequestOptionsJSON,
    ceremony?: CeremonyOptions,
  ) => Promise<AuthenticationResponseJSON>;
  /** What the authenticator will report next, so a test can assert on it. */
  readonly counter: () => number;
}

/**
 * Bytes backed by a plain `ArrayBuffer`.
 *
 * WebCrypto and the CBOR helpers both demand this narrower type rather than
 * `Uint8Array<ArrayBufferLike>`, which is what `TextEncoder` and friends produce -
 * a `SharedArrayBuffer` cannot be handed to either.
 */
type Bytes = Uint8Array<ArrayBuffer>;

/** Copies anything array-like into a plain-buffer `Uint8Array`. */
function bytes(source: ArrayLike<number>): Bytes {
  const copy = new Uint8Array(new ArrayBuffer(source.length));
  copy.set(source);
  return copy;
}

/** UTF-8 bytes of a string, in the buffer type WebCrypto accepts. */
function utf8(value: string): Bytes {
  return bytes(new TextEncoder().encode(value));
}

/** Joins byte arrays, which authenticator data is built by concatenating. */
function concat(...parts: readonly Uint8Array[]): Bytes {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

/** A big-endian unsigned integer of `length` bytes. */
function bigEndian(value: number, length: number): Bytes {
  const encoded = new Uint8Array(new ArrayBuffer(length));
  for (let index = length - 1; index >= 0; index -= 1) {
    encoded[index] = (value >>> ((length - 1 - index) * 8)) & 0xff;
  }
  return encoded;
}

/** SHA-256, which both the RP ID hash and the signed client data hash need. */
async function sha256(input: Bytes): Promise<Bytes> {
  return bytes(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}

/**
 * The COSE encoding of an EC2 public key.
 *
 * The map keys are the negative and positive labels COSE defines rather than
 * names; `decodeCredentialPublicKey` on the server reads exactly these.
 */
function coseKey(x: Bytes, y: Bytes): Bytes {
  return bytes(
    isoCBOR.encode(
      new Map<number, number | Bytes>([
        [1, COSE_KTY_EC2],
        [3, COSE_ALG_ES256],
        [-1, COSE_CRV_P256],
        [-2, x],
        [-3, y],
      ]),
    ),
  );
}

/**
 * Converts WebCrypto's raw `r || s` signature into the DER encoding WebAuthn uses.
 *
 * The authenticator is specified to return an ASN.1 DER ECDSA signature, and the
 * server's verifier reads one; WebCrypto produces the fixed-width concatenation
 * instead, so the two have to be reconciled somewhere.
 */
function derSignature(raw: Bytes): Bytes {
  const half = raw.length / 2;

  /** One integer, minimally encoded and sign-padded as DER requires. */
  const integer = (value: Uint8Array): Bytes => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) {
      start += 1;
    }
    const trimmed = value.slice(start);
    const padded =
      (trimmed[0] ?? 0) >= 0x80 ? concat(bytes([0]), trimmed) : trimmed;
    return concat(bytes([0x02, padded.length]), padded);
  };

  const body = concat(integer(raw.slice(0, half)), integer(raw.slice(half)));
  return concat(bytes([0x30, body.length]), body);
}

/** The `clientDataJSON` bytes for one ceremony. */
function clientData(
  type: "webauthn.create" | "webauthn.get",
  challenge: string,
  origin: string,
): Bytes {
  return utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

/** How a virtual authenticator should behave from the start. */
export interface VirtualAuthenticatorOptions {
  /** The origin its ceremonies claim, which must be the deployment's public URL. */
  readonly origin: string;
  /**
   * The counter it starts at, and increments from.
   *
   * Zero models a platform authenticator that does not count, which is the case
   * the counter rule must not lock out. A non-zero start models a security key.
   */
  readonly counter?: number;
}

/**
 * Builds a software authenticator holding one freshly generated credential.
 *
 * @param options - The origin to claim, and where its counter starts.
 * @returns An authenticator that can register once and then assert repeatedly.
 * @example
 * ```ts
 * const key = await createVirtualAuthenticator({ origin: TEST_PUBLIC_URL });
 * const attestation = await key.register(creationOptions);
 * ```
 */
export async function createVirtualAuthenticator(
  options: VirtualAuthenticatorOptions,
): Promise<VirtualAuthenticator> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const x = bytes(isoBase64URL.toBuffer(jwk.x ?? ""));
  const y = bytes(isoBase64URL.toBuffer(jwk.y ?? ""));

  const credentialIdBytes = bytes(crypto.getRandomValues(new Uint8Array(32)));
  const credentialId = isoBase64URL.fromBuffer(credentialIdBytes);
  let counter = options.counter ?? 0;

  /** The authenticator data both ceremonies begin with. */
  const authenticatorData = async (
    rpId: string,
    flags: number,
    signCount: number,
    attested?: Uint8Array,
  ): Promise<Bytes> =>
    concat(
      await sha256(utf8(rpId)),
      new Uint8Array([flags]),
      bigEndian(signCount, 4),
      ...(attested === undefined ? [] : [attested]),
    );

  return {
    credentialId,
    counter: () => counter,

    register: async (creation, ceremony = {}) => {
      const verified = ceremony.userVerified ?? true;
      const authData = await authenticatorData(
        creation.rp.id ?? "",
        FLAG_USER_PRESENT |
          (verified ? FLAG_USER_VERIFIED : 0) |
          FLAG_ATTESTED_CREDENTIAL_DATA,
        ceremony.counter ?? counter,
        concat(
          AAGUID,
          bigEndian(credentialIdBytes.length, 2),
          credentialIdBytes,
          coseKey(x, y),
        ),
      );

      const attestationObject = bytes(
        isoCBOR.encode(
          new Map<string, unknown>([
            ["fmt", "none"],
            ["attStmt", new Map()],
            ["authData", authData],
          ]) as Parameters<typeof isoCBOR.encode>[0],
        ),
      );

      return {
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: isoBase64URL.fromBuffer(
            clientData(
              "webauthn.create",
              creation.challenge,
              ceremony.origin ?? options.origin,
            ),
          ),
          attestationObject: isoBase64URL.fromBuffer(attestationObject),
          transports: ["internal"],
        },
      };
    },

    authenticate: async (request, ceremony = {}) => {
      const verified = ceremony.userVerified ?? true;
      // A real authenticator increments before signing, which is what makes the
      // counter rule meaningful; a test wanting a stalled counter says so.
      counter += 1;
      const reported = ceremony.counter ?? counter;

      const authData = await authenticatorData(
        request.rpId ?? "",
        FLAG_USER_PRESENT | (verified ? FLAG_USER_VERIFIED : 0),
        reported,
      );
      const clientDataBytes = clientData(
        "webauthn.get",
        request.challenge,
        ceremony.origin ?? options.origin,
      );
      const signed = concat(authData, await sha256(clientDataBytes));
      const raw = bytes(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            pair.privateKey,
            signed,
          ),
        ),
      );

      return {
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: isoBase64URL.fromBuffer(clientDataBytes),
          authenticatorData: isoBase64URL.fromBuffer(authData),
          signature: isoBase64URL.fromBuffer(derSignature(raw)),
        },
      };
    },
  };
}
