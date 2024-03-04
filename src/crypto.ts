import { webcrypto } from "crypto";
import { randomBytes } from 'crypto';

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};

export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" },
    },
    true,
    ["encrypt", "decrypt"]
  );
  return { publicKey, privateKey };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  const base64Key = arrayBufferToBase64(exportedKeyBuffer);
  return base64Key;
}


export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (key) {
    const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
    const exportedKeyBuffer = new Uint8Array(exportedKey);
    const base64Key = arrayBufferToBase64(exportedKeyBuffer);
    return base64Key;
  }
  return null;
}



// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "spki",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" },
    },
    true,
    ["encrypt"]
  );
  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" },
    },
    true,
    ["decrypt"]
  );
  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const dataBuffer = base64ToArrayBuffer(b64Data);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    dataBuffer
  );
  const encryptedDataArray = new Uint8Array(encryptedData);
  const encryptedDataB64 = arrayBufferToBase64(encryptedDataArray);
  return encryptedDataB64;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  const encryptedDataArray = base64ToArrayBuffer(data);
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedDataArray
  );
  const decryptedDataArray = new Uint8Array(decryptedData);
  const decryptedDataB64 = arrayBufferToBase64(decryptedDataArray);
  return decryptedDataB64;
}

// ######################
// ### Symmetric keys ###
// ######################

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  const keyBytes = randomBytes(32);
  const key = await webcrypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const keyBuffer = await webcrypto.subtle.exportKey("raw", key);
  const keyArray = Array.from(new Uint8Array(keyBuffer));
  const keyBase64 = btoa(keyArray.map(byte => String.fromCharCode(byte)).join(""));
  return keyBase64;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyArray = Array.from(atob(strKey), c => c.charCodeAt(0));
  const keyBuffer = new Uint8Array(keyArray);
  const key = await webcrypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  try {
    const iv = crypto.getRandomValues(new Uint8Array(16)); // Initialization Vector (IV) for AES-CBC
    const dataBuffer = new TextEncoder().encode(data);

    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      dataBuffer
    );

    const combinedBuffer = new Uint8Array(iv.length + encryptedData.byteLength);
    combinedBuffer.set(iv);
    combinedBuffer.set(new Uint8Array(encryptedData), iv.length);

    const encryptedDataB64 = arrayBufferToBase64(combinedBuffer);

    return encryptedDataB64;
  } 
  catch (error) {
    console.error('Error encrypting with symmetric key:', error);
    throw error;
  }
}

// Decrypt a message using a symmetric key
export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  try {
    const key = await importSymKey(strKey);
    const combinedBuffer = base64ToArrayBuffer(encryptedData);
    const iv = combinedBuffer.slice(0, 16);
    const encryptedDataBuffer = combinedBuffer.slice(16);

    const decryptedData = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      key,
      encryptedDataBuffer
    );

    const decryptedDataStr = new TextDecoder().decode(new Uint8Array(decryptedData));

    return decryptedDataStr;
  } catch (error) {
    console.error('Error decrypting with symmetric key:', error);
    throw error;
  }
}