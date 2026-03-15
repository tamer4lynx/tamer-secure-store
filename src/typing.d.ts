declare var NativeModules: {
  SecureStoreModule?: {
    getValueWithKeyAsync(key: string, optionsJson: string, callback: (json: string) => void): void
    setValueWithKeyAsync(key: string, value: string, optionsJson: string, callback: (json: string) => void): void
    deleteValueWithKeyAsync(key: string, optionsJson: string, callback: (json: string) => void): void
    getValueWithKeySync(key: string, optionsJson: string): string | null
    setValueWithKeySync(key: string, value: string, optionsJson: string): void
    canUseBiometricAuthentication(): boolean
  }
}
