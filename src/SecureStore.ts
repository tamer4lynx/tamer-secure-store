export type KeychainAccessibilityConstant = number

export const AFTER_FIRST_UNLOCK: KeychainAccessibilityConstant = 0
export const AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: KeychainAccessibilityConstant = 1
export const ALWAYS: KeychainAccessibilityConstant = 2
export const WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: KeychainAccessibilityConstant = 3
export const ALWAYS_THIS_DEVICE_ONLY: KeychainAccessibilityConstant = 4
export const WHEN_UNLOCKED: KeychainAccessibilityConstant = 5
export const WHEN_UNLOCKED_THIS_DEVICE_ONLY: KeychainAccessibilityConstant = 6

export type SecureStoreOptions = {
  keychainService?: string
  requireAuthentication?: boolean
  authenticationPrompt?: string
  keychainAccessible?: KeychainAccessibilityConstant
  accessGroup?: string
}

/** Use with `useInitData()` from the Lynx bundle so storage is scoped per logical app (tamerAppKey from dev server meta), not per dev-server URL. */
export function resolveKeychainServiceWithTamerIdentity(initData: unknown, baseService = 'key_v1'): string {
  if (initData == null || typeof initData !== 'object') return baseService
  const key = (initData as Record<string, unknown>).tamerAppKey
  if (typeof key !== 'string' || !key.trim()) return baseService
  return `${baseService}:${key.trim()}`
}

function ensureValidKey(key: string) {
  if (!/^[\w.-]+$/.test(key)) {
    throw new Error(
      `Invalid key provided to SecureStore. Keys must not be empty and contain only alphanumeric characters, ".", "-", and "_".`
    )
  }
}

function isValidValue(value: string) {
  return typeof value === 'string'
}

function optionsToJson(options: SecureStoreOptions = {}): string {
  return JSON.stringify({
    keychainService: options.keychainService ?? 'key_v1',
    requireAuthentication: options.requireAuthentication ?? false,
    authenticationPrompt: options.authenticationPrompt ?? ' ',
    keychainAccessible: options.keychainAccessible,
    accessGroup: options.accessGroup,
  })
}

export async function getItemAsync(
  key: string,
  options: SecureStoreOptions = {}
): Promise<string | null> {
  ensureValidKey(key)
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  if (!mod?.getValueWithKeyAsync) return null
  return new Promise((resolve, reject) => {
    mod.getValueWithKeyAsync(key, optionsToJson(options), (json: string) => {
      try {
        const r = JSON.parse(json)
        if (r.error) reject(new Error(r.error))
        else resolve(r.value ?? null)
      } catch (e) {
        reject(e)
      }
    })
  })
}

export async function setItemAsync(
  key: string,
  value: string,
  options: SecureStoreOptions = {}
): Promise<void> {
  ensureValidKey(key)
  if (!isValidValue(value)) {
    throw new Error(
      `Invalid value provided to SecureStore. Values must be strings; consider JSON-encoding your values if they are serializable.`
    )
  }
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  if (!mod?.setValueWithKeyAsync) return
  return new Promise((resolve, reject) => {
    mod.setValueWithKeyAsync(key, value, optionsToJson(options), (json: string) => {
      try {
        const r = JSON.parse(json)
        if (r.error) reject(new Error(r.error))
        else resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
}

export async function deleteItemAsync(
  key: string,
  options: SecureStoreOptions = {}
): Promise<void> {
  ensureValidKey(key)
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  if (!mod?.deleteValueWithKeyAsync) return
  return new Promise((resolve, reject) => {
    mod.deleteValueWithKeyAsync(key, optionsToJson(options), (json: string) => {
      try {
        const r = JSON.parse(json)
        if (r.error) reject(new Error(r.error))
        else resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
}

export function getItem(key: string, options: SecureStoreOptions = {}): string | null {
  ensureValidKey(key)
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  if (!mod?.getValueWithKeySync) return null
  return mod.getValueWithKeySync(key, optionsToJson(options))
}

export function setItem(
  key: string,
  value: string,
  options: SecureStoreOptions = {}
): void {
  ensureValidKey(key)
  if (!isValidValue(value)) {
    throw new Error(
      `Invalid value provided to SecureStore. Values must be strings; consider JSON-encoding your values if they are serializable.`
    )
  }
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  mod?.setValueWithKeySync(key, value, optionsToJson(options))
}

export function canUseBiometricAuthentication(): boolean {
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  return mod?.canUseBiometricAuthentication?.() ?? false
}

export async function isAvailableAsync(): Promise<boolean> {
  const mod = typeof NativeModules !== 'undefined' ? NativeModules?.SecureStoreModule : null
  return !!mod?.getValueWithKeyAsync
}
