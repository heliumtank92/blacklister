import crypto from 'crypto'
import DEBUG from '../DEBUG.mjs'
import { SERVICE, IS_PRODUCTION } from '../CONFIG.mjs'

const DEFAULT_IV_HEX = '00000000000000000000000000000000'

const KeyMoizer = new Map()

export default class Crypto {
  constructor (config = {}) {
    this.MASTER_KEY_HEX = config.ENCRYPT_MASTER_KEY_HEX || ''
    this.ENCRYPTION_KEY_HEX = config.ENCRYPT_ENCRYPTION_KEY_HEX || ''
    this.MASTER_IV_HEX = config.ENCRYPT_MASTER_IV_HEX || DEFAULT_IV_HEX

    this.KEY_BUFFER = Buffer.from(this.MASTER_KEY_HEX, 'hex')
    this.IV_BUFFER = Buffer.from(this.MASTER_IV_HEX, 'hex')
    this.ENCRYPT_KEYS = config.ENCRYPT_KEYS || []

    this.SHOULD_ENCRYPT = (
      !DEBUG.disableEncrypt &&
      this.MASTER_KEY_HEX &&
      this.ENCRYPT_KEYS &&
      this.ENCRYPT_KEYS.length > 0
    )

    this.#_warnings()

    this.encrypt = this.encrypt.bind(this)
    this.decrypt = this.decrypt.bind(this)
  }

  encrypt (key, value) {
    if (
      !IS_PRODUCTION ||
      !key ||
      !this.SHOULD_ENCRYPT ||
      !this.ENCRYPT_KEYS.includes(key)
    ) { return { encrypted: false, encryptedValue: value } }

    const typeofValue = typeof value

    if (
      typeofValue !== 'string' &&
      typeofValue !== 'number' &&
      (typeofValue === 'object' && value instanceof Array && typeof value[0] === 'object')
    ) { return { encrypted: false, encryptedValue: value } }

    if (value instanceof Array) {
      return { encrypted: true, encryptedValue: value.map(this.#_encrypt) }
    } else {
      return { encrypted: true, encryptedValue: this.#_encrypt(value) }
    }
  }

  decrypt (key, value) {
    if (
      !IS_PRODUCTION ||
      !key ||
      !this.SHOULD_ENCRYPT ||
      !this.ENCRYPT_KEYS.includes(key)
    ) { return { decrypted: false, decryptedValue: value } }

    const typeofValue = typeof value

    if (
      typeofValue !== 'string' &&
      typeofValue !== 'number' &&
      (typeofValue === 'object' && value instanceof Array && typeof value[0] === 'object')
    ) { return { decrypted: false, decryptedValue: value } }

    if (value instanceof Array) {
      return { decrypted: true, decryptedValue: value.map(this.#_decrypt) }
    } else {
      return { decrypted: true, decryptedValue: this.#_decrypt(value) }
    }
  }

  #_encrypt (plaintext = '') {
    const encryptor = crypto.createCipheriv('aes-128-cbc', this.KEY_BUFFER, this.IV_BUFFER)
    const cipherTextBuffer = Buffer.concat([encryptor.update(`${plaintext}`, 'utf8'), encryptor.final()])
    const cipherText = cipherTextBuffer.toString('base64')
    return cipherText
  }

  #_decrypt (cipherText = '') {
    const cipherTextBuffer = Buffer.from(cipherText, 'base64')
    const decryptor = crypto.createDecipheriv('aes-128-cbc', this.KEY_BUFFER, this.IV_BUFFER)
    const plaintextBuffer = Buffer.concat([decryptor.update(cipherTextBuffer), decryptor.final()])
    const plaintext = plaintextBuffer.toString('utf8')
    return plaintext
  }

  #_warnings () {
    if (IS_PRODUCTION) {
      if (DEBUG.disableEncrypt) {
        console.warn(`[${SERVICE} Blacklister] Encryption Disabled as DEBUG is Set in Environment`)
      }

      if (!this.MASTER_KEY_HEX) {
        console.warn(`[${SERVICE} Blacklister] Encryption Disabled as ENCRYPT_MASTER_KEY_HEX is Not Configured`)
      }

      if (!this.ENCRYPT_KEYS || !this.ENCRYPT_KEYS.length) {
        console.warn(`[${SERVICE} Blacklister] Encryption Disabled as ENCRYPT_KEYS is Not Configured`)
      }
    } else {
      console.warn(`[${SERVICE} Blacklister] Encryption Disabled for Non-Production Mode`)
    }
  }
}
