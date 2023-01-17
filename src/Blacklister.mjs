import Crypto from './lib/Crypto.mjs'
import Hash from './lib/Hash.mjs'

export default class Blacklister {
  constructor (config = {}) {
    const crypto = new Crypto(config)
    const hash = new Hash(config)

    this.encrypt = crypto.encrypt
    this.decrypt = crypto.decrypt
    this.hash = hash.hash

    this.blacklist = this.blacklist.bind(this)
    this.whitelist = this.whitelist.bind(this)
  }

  blacklist (object = {}) {
    const iterable = object instanceof Array ? object : (object instanceof Object && object) ? object : {}

    for (const key in iterable) {
      const value = iterable[key]

      const { encrypted, encryptedValue } = this.encrypt(key, value)
      if (encrypted) {
        object[key] = encryptedValue
        continue
      }

      const { hashed, hashedValue } = this.hash(key, value)
      if (hashed) {
        object[key] = hashedValue
        continue
      }

      if (value !== null && (value instanceof Array || value instanceof Object)) {
        object[key] = this.blacklist(value)
      }

      object[key] = value
      continue
    }

    return object
  }

  whitelist (object = {}) {
    const iterable = object instanceof Array ? object : (object instanceof Object && object) ? object : {}

    for (const key in iterable) {
      const value = iterable[key]

      const { decrypted, decryptedValue } = this.decrypt(key, value)
      if (decrypted) {
        object[key] = decryptedValue
        continue
      }

      if (value !== null && (value instanceof Array || value instanceof Object)) {
        object[key] = this.whitelist(value)
      }

      object[key] = value
      continue
    }

    return object
  }
}
