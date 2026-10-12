/**
 * Recover a wallet's passkey public key from a signature, when nothing stored it.
 *
 * The wallet address is SHA-256 of the 65-byte P-256 public key, salted into the
 * factory's deployer derivation — a one-way function. WebAuthn makes that worse:
 * the public key is handed out exactly once, in the registration response, and
 * never again. Every later assertion returns a signature and nothing else.
 *
 * So a wallet whose key was not persisted at creation looks permanently
 * unspendable: `deploy()` needs the key, the secure store does not have it, and
 * the on-chain breadcrumbs carry only `veil:wallet` because the write that
 * should have recorded `veil:pk1`/`veil:pk2` had no key to record. Wallets in
 * that state hold real money at an address that cannot be deployed.
 *
 * ECDSA is the way out. A signature (r, s) over a known message hash is
 * satisfied by at most four public keys, and they can be computed from the
 * signature alone — this is how Ethereum gets a sender address out of a
 * transaction. Here the candidate set is even easier to resolve, because the
 * wallet address itself decides: exactly one candidate derives to it.
 *
 * That makes the key recoverable from the passkey forever, with no backup, no
 * breadcrumbs and no server — one assertion is enough.
 *
 * Low-S normalisation (see `derToRawSignature`) is why both `s` and `n − s` are
 * tried: flipping s flips which recovery bit yields the original key, so the
 * four combinations below cover a signature whether or not it was normalised.
 */

import { p256 } from '@noble/curves/p256.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';
import { computeWalletAddress } from '@veil/sdk';

import { getFeePayerAddress } from './activity';
import { getNetwork } from './network';
import { assertForKeyRecovery, type RecoveryAssertion } from './passkey';
import { SDK_ADDRESS, SDK_KEY_ID, SDK_PUBLIC_KEY, setSdkItems } from './sdkStorage';
import { writeBreadcrumbs } from './walletBreadcrumbs';
import { getPasskeyId, getSignerSecret, setPasskeyCredential } from './walletStore';

/** Order of the P-256 group, for the `n − s` half of the candidate set. */
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

function toBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

/**
 * The public keys that could have produced this assertion (at most four).
 *
 * WebAuthn signs SHA-256(authData ‖ SHA-256(clientDataJSON)) — the same preimage
 * `findMatchingSigner` verifies against, built here to recover rather than check.
 */
export function recoverPublicKeyCandidates(assertion: RecoveryAssertion): Uint8Array[] {
  const clientDataHash = sha256(assertion.clientDataJSON);
  const signed = new Uint8Array(assertion.authData.length + clientDataHash.length);
  signed.set(assertion.authData, 0);
  signed.set(clientDataHash, assertion.authData.length);
  const messageHash = sha256(signed);

  if (assertion.signature.length !== 64) return [];
  const r = toBigInt(assertion.signature.subarray(0, 32));
  const s = toBigInt(assertion.signature.subarray(32));

  const seen = new Set<string>();
  const candidates: Uint8Array[] = [];
  for (const candidateS of [s, P256_ORDER - s]) {
    for (let bit = 0; bit < 2; bit++) {
      try {
        const point = new p256.Signature(r, candidateS).addRecoveryBit(bit).recoverPublicKey(messageHash);
        const bytes = point.toRawBytes(false);
        const hex = Buffer.from(bytes).toString('hex');
        if (bytes.length === 65 && !seen.has(hex)) {
          seen.add(hex);
          candidates.push(bytes);
        }
      } catch {
        // A recovery bit that names no curve point is simply not a candidate.
      }
    }
  }
  return candidates;
}

/**
 * Ask the passkey for one signature and recover the key `walletAddress` was
 * built from, or null when no candidate derives to it.
 *
 * A candidate is accepted only when it reproduces the wallet address exactly,
 * which is the same invariant `resolveWalletPublicKey` already enforces: a key
 * that derives elsewhere would deploy a different, empty contract. So a user who
 * picks the wrong passkey gets null, never someone else's wallet.
 *
 * On success the key is written back everywhere it should have been in the first
 * place — secure store, the SDK's mirror, and the on-chain breadcrumbs — so this
 * costs one passkey prompt once, not on every spend.
 */
export async function recoverWalletPublicKey(walletAddress: string): Promise<Uint8Array | null> {
  const credentialId = await getPasskeyId().catch(() => null);
  const assertion = await assertForKeyRecovery(credentialId);
  if (!assertion) return null;

  const net = getNetwork();
  const match = recoverPublicKeyCandidates(assertion).find(
    (candidate) => computeWalletAddress(net.factoryContractId, candidate, net.networkPassphrase) === walletAddress,
  );
  if (!match) return null;

  const hex = Buffer.from(match).toString('hex');
  await setPasskeyCredential(assertion.credentialId, hex).catch(() => undefined);
  await writeSdkMirror(walletAddress, assertion.credentialId, hex).catch(() => undefined);

  // Breadcrumbs are what make this wallet recoverable on a different device, and
  // they are the record that was missing. Best-effort, as everywhere else: the
  // key is already usable locally without them.
  const feePayer = await getFeePayerAddress();
  if (feePayer) {
    const secret = await getSignerSecret().catch(() => null);
    if (secret) void writeBreadcrumbs(secret, walletAddress, match).catch(() => undefined);
  }

  return match;
}

/** The SDK's AsyncStorage keys, namespaced per network exactly as walletStore does. */
async function writeSdkMirror(address: string, credentialId: string, publicKeyHex: string): Promise<void> {
  await setSdkItems([
    [SDK_ADDRESS, address],
    [SDK_KEY_ID, credentialId],
    [SDK_PUBLIC_KEY, publicKeyHex],
  ]);
}
