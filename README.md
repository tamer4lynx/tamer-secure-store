# tamer-secure-store

Secure key-value storage for Lynx. Uses Android KeyStore + AES-256-GCM and iOS Keychain, with optional biometric authentication.

## Installation

```bash
npm install @tamer4lynx/tamer-secure-store
```

Add to your app's dependencies and run `t4l link`. Uses **lynx.ext.json** (RFC standard).

## Usage

```ts
import * as SecureStore from '@tamer4lynx/tamer-secure-store'

await SecureStore.setItemAsync('token', 'secret-value')
const value = await SecureStore.getItemAsync('token')
await SecureStore.deleteItemAsync('token')

const canUseBiometrics = SecureStore.canUseBiometricAuthentication()
```

## Options

- `keychainService` – Keychain/KeyStore identifier (default: `key_v1`)
- `requireAuthentication` – Require biometric auth to access (Face ID, fingerprint)
- `authenticationPrompt` – Message shown in biometric prompt
- `keychainAccessible` – iOS keychain accessibility (e.g. `SecureStore.WHEN_UNLOCKED`)
- `accessGroup` – iOS app group for sharing (optional)

## iOS: Biometric authentication

When using `requireAuthentication: true`, add to your app's `Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access stored credentials</string>
```

Without this key, storing or reading values with `requireAuthentication` will fail.

## Android: Backup exclusion

SecureStore data is stored in `SharedPreferences` with `MODE_PRIVATE`. For production apps, consider excluding SecureStore from Android Auto Backup by adding to `android:fullBackupContent` or `android:dataExtractionRules` in your manifest. See [Android backup documentation](https://developer.android.com/guide/topics/data/autobackup) for details.
