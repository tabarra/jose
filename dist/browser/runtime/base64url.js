import { encoder, decoder } from '../lib/buffer_utils.js';
import globalThis from './global.js';
export const encodeBase64 = (input) => {
    let unencoded = input;
    if (typeof unencoded === 'string') {
        unencoded = encoder.encode(unencoded);
    }
    const CHUNK_SIZE = 0x8000;
    const arr = [];
    for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
    }
    return globalThis.btoa(arr.join(''));
};
export const encode = (input) => {
    return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
export const decodeBase64 = (encoded) => {
    return new Uint8Array(globalThis
        .atob(encoded)
        .split('')
        .map((c) => c.charCodeAt(0)));
};
export const decode = (input) => {
    let encoded = input;
    if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
    }
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    try {
        return decodeBase64(encoded);
    }
    catch (_a) {
        throw new TypeError('The input to be decoded is not correctly encoded.');
    }
};