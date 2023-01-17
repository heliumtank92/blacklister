import crypto from 'crypto'
import DEBUG from '../DEBUG.mjs'
import { SERVICE, IS_PRODUCTION } from '../CONFIG.mjs'

export default class Hash {
  constructor (config = {}) {
    this.HASH_KEYS = config.HASH_KEYS
    this.HASH_SECRET = config.HASH_SECRET

    this.SHOULD_HASH = (
      !DEBUG.disableHash &&
      this.HASH_KEYS &&
      (this.HASH_KEYS.length > 0)
    )

    this.#_warnings()

    this.hash = this.hash.bind(this)
  }

  hash (key, value) {
    if (
      !IS_PRODUCTION ||
      !key ||
      !this.SHOULD_HASH ||
      !this.HASH_KEYS.includes(key)
    ) { return { hashed: false, hashedValue: value } }

    const typeofValue = typeof value

    if (
      typeofValue !== 'string' &&
      typeofValue !== 'number' &&
      (typeofValue === 'object' && value instanceof Array && typeof value[0] === 'object')
    ) { return { encrypted: false, encryptedValue: value } }

    if (value instanceof Array) {
      return { hashed: true, hashedValue: value.map(this.#_hash) }
    } else {
      return { hashed: true, hashedValue: this.#_hash(value) }
    }
  }

  #_hash (value = '') {
    const hasher = crypto.createHash('sha256', this.HASH_SECRET)
    const hashValue = hasher.update(value).digest('base64')
    return hashValue
  }

  #_warnings () {
    if (IS_PRODUCTION) {
      if (DEBUG.disableHash) {
        console.warn(`[${SERVICE} Blacklister] Hashing Disabled as DEBUG is Set in Environment`)
      }

      if (!this.HASH_SECRET) {
        console.warn(`[${SERVICE} Blacklister] Hashing without Secret as HASH_SECRET is Not Configured`)
      }

      if (!this.HASH_KEYS || !this.HASH_KEYS.length) {
        console.warn(`[${SERVICE} Blacklister] Hashing Disabled as HASH_KEYS is Not Configured`)
      }
    } else {
      console.warn(`[${SERVICE} Blacklister] Hashing Disabled for Non-Production Mode`)
    }
  }
}
