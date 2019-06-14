/**
 * Node.js eccrypto implementation.
 * @module eccrypto
 */

"use strict";

const EC_GROUP_ORDER = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const ZERO32 = Buffer.alloc(32, 0);

// try to use secp256k1, fallback to browser implementation
try {
  var secp256k1 = require("secp256k1");
  var ecdh = require("./build/Release/ecdh");
} catch (e) {
  console.error('Reverting to browser version');
  return (module.exports = require("./browser"));
}

function isScalar (x) {
  return Buffer.isBuffer(x) && x.length === 32;
}

function privateKeyVerify(privateKey) {
  if (!isScalar(privateKey))
  {
    return false;
  }
  return privateKey.compare(ZERO32) > 0 && // > 0
  privateKey.compare(EC_GROUP_ORDER) < 0; // < G
}

/**
 * Get compressed version of public key.
 */
exports.publicKeyCreate = function(privateKey) { // jshint ignore:line
  assert(privateKey.length === 32, "Bad private key");
  assert(privateKeyVerify(privateKey), "Bad private key");
  // See https://github.com/wanderer/secp256k1-node/issues/46
  return secp256k1.publicKeyCreate(privateKey);
};

/**
 * Create an ECDSA signature.
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed
 * signature and rejects on bad key or message.
 */
exports.sign = function(privateKey, msg) {
  assert(privateKey.length === 32, "Bad private key");
  assert(privateKeyVerify(privateKey), "Bad private key");
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  msg = pad32(msg);
  var sig = secp256k1.signSync(msg, privateKey).signature;
  return secp256k1.signatureExport(sig);
};

/**
 * Verify an ECDSA signature.
 * @param {Buffer} publicKey - A 65-byte public key
 * @param {Buffer} msg - The message being verified
 * @param {Buffer} sig - The signature
 * and rejects on bad key or signature.
 */
exports.verify = function(publicKey, msg, sig) {
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  msg = pad32(msg);
  sig = secp256k1.signatureImport(sig);
  if (secp256k1.verifySync(msg, sig, publicKey)) {
    return true;
  } else {
    throw new Error("Bad signature");
  }
};