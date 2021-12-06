import { encoder, concat, uint32be, lengthAndInput, concatKdf } from '../../lib/buffer_utils.js'
import crypto, { isCryptoKey } from './webcrypto.js'
import { checkEncCryptoKey } from '../../lib/crypto_key.js'
import digest from './digest.js'
import invalidKeyInput from '../../lib/invalid_key_input.js'
import { types } from './is_key_like.js'

export async function deriveKey(
  publicKey: unknown,
  privateKey: unknown,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array = new Uint8Array(0),
  apv: Uint8Array = new Uint8Array(0),
) {
  if (!isCryptoKey(publicKey)) {
    throw new TypeError(invalidKeyInput(publicKey, ...types))
  }
  checkEncCryptoKey(publicKey, 'ECDH-ES')
  if (!isCryptoKey(privateKey)) {
    throw new TypeError(invalidKeyInput(privateKey, ...types))
  }
  checkEncCryptoKey(privateKey, 'ECDH-ES', 'deriveBits', 'deriveKey')

  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  )

  if (!privateKey.usages.includes('deriveBits')) {
    throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"')
  }

  let length: number
  if (publicKey.algorithm.name === 'X25519') {
    length = 256
  } else if (publicKey.algorithm.name === 'X448') {
    length = 448
  } else {
    length =
      Math.ceil(parseInt((<EcKeyAlgorithm>publicKey.algorithm).namedCurve.substr(-3), 10) / 8) << 3
  }

  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: publicKey.algorithm.name,
        public: publicKey,
      },
      privateKey,
      length,
    ),
  )

  return concatKdf(digest, sharedSecret, keyLength, value)
}

export async function generateEpk(key: unknown) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, ...types))
  }

  return crypto.subtle.generateKey(<EcKeyAlgorithm>key.algorithm, true, ['deriveBits'])
}

export function ecdhAllowed(key: unknown) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, ...types))
  }
  return (
    ['P-256', 'P-384', 'P-521'].includes((<EcKeyAlgorithm>key.algorithm).namedCurve) ||
    key.algorithm.name === 'X25519' ||
    key.algorithm.name === 'X448'
  )
}
