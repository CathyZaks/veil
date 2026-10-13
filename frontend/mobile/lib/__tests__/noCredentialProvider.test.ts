/**
 * Android saying it has nowhere to put a passkey.
 *
 * The raw string — "createCredentialAsync no provider dependencies found" —
 * reads as a missing gradle dependency, and cost an hour of looking at our own
 * build before the answer turned out to be a setting on the phone. Both
 * Credential Manager artifacts are shipped by react-native-passkeys; this is
 * the device reporting that no provider is enabled to store the credential.
 */

import { isNoCredentialProvider, NO_CREDENTIAL_PROVIDER_MESSAGE } from '../passkey';

describe('isNoCredentialProvider', () => {
  it.each([
    'createCredentialAsync no provider dependencies found - please ensure the desired provider dependencies are added',
    'androidx.credentials.exceptions.CreateCredentialProviderConfigurationException: no provider dependencies found',
    'No create options available from any provider for createCredential',
  ])('recognises %s', (message) => {
    expect(isNoCredentialProvider(new Error(message))).toBe(true);
  });

  // A cancelled prompt and an orphaned credential have their own answers, and
  // sending either to "turn on a passkey provider" would be wrong.
  it.each([
    'The operation was cancelled by the user',
    'androidx.credentials.exceptions.NoCredentialException: no credentials available',
    'Network request failed',
  ])('does not claim %s', (message) => {
    expect(isNoCredentialProvider(new Error(message))).toBe(false);
  });

  it('survives a non-Error being thrown', () => {
    expect(isNoCredentialProvider(undefined)).toBe(false);
    expect(isNoCredentialProvider('no provider dependencies found')).toBe(true);
  });

  // The whole point is that it names the setting to change.
  it('tells the user where to go', () => {
    expect(NO_CREDENTIAL_PROVIDER_MESSAGE).toMatch(/Settings/);
    expect(NO_CREDENTIAL_PROVIDER_MESSAGE).toMatch(/Google Password Manager/);
  });
});
