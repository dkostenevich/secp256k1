"use strict";

var EC = require("elliptic").ec;

var ec = new EC("secp256k1");

const EC_GROUP_ORDER = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const ZERO32 = Buffer.alloc(32, 0);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
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
  let compressed = true;
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, "arr"));
};

exports.sign = function(privateKey, msg) {
  assert(privateKey.length === 32, "Bad private key");
  assert(privateKeyVerify(privateKey), "Bad private key");
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  return Buffer.from(ec.sign(msg, privateKey, {canonical: true}).toDER());
};

exports.verify = function(publicKey, msg, sig) {
  assert(publicKey.length === 65 || publicKey.length === 33, "Bad public key");
  if (publicKey.length === 65)
  {
    assert(publicKey[0] === 4, "Bad public key");
  }
  if (publicKey.length === 33)
  {
    assert(publicKey[0] === 2 || publicKey[0] === 3, "Bad public key");
  }
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  if (ec.verify(msg, sig, publicKey)) {
    return true;
  } else {
    throw new Error("Bad signature");
  }
};
