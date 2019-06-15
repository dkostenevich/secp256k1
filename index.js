"use strict";

var BN = require('bn.js');
var EC = require("elliptic").ec;
var ec = new EC("secp256k1");
var ecparams = ec.curve;

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

exports.sign = function(msg, privateKey) {
  assert(privateKey.length === 32, "Bad private key");
  assert(privateKeyVerify(privateKey), "Bad private key");
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  var result = ec.sign(msg, privateKey, {canonical: true});
  return {
    signature: Buffer.concat([
      result.r.toArrayLike(Buffer, 'be', 32),
      result.s.toArrayLike(Buffer, 'be', 32)
    ]),
    recovery: result.recoveryParam
   }
};

function loadCompressedPublicKey(first, xBuffer) {
  var x = new BN(xBuffer);

  if (x.cmp(ecparams.p) >= 0) 
    return null;

  x = x.toRed(ecparams.red);

  var y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt();
  if ((first === 0x03) !== y.isOdd()) 
    y = y.redNeg();

  return ec.keyPair({ pub: { x: x, y: y } });
}

function loadUncompressedPublicKey(first, xBuffer, yBuffer) {
  var x = new BN(xBuffer);
  var y = new BN(yBuffer);

  if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) 
    return null;

  x = x.toRed(ecparams.red);
  y = y.toRed(ecparams.red);

  if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) 
    return null;

  var x3 = x.redSqr().redIMul(x)
  if (!y.redSqr().redISub(x3.redIAdd(ecparams.b)).isZero()) 
    return null;

  return ec.keyPair({ pub: { x: x, y: y } });
}

function loadPublicKey(publicKey) {
  var first = publicKey[0];
  switch (first) {
    case 0x02:
    case 0x03:
      if (publicKey.length !== 33) return null;
      return loadCompressedPublicKey(first, publicKey.slice(1, 33));
    case 0x04:
    case 0x06:
    case 0x07:
      if (publicKey.length !== 65) return null;
      return loadUncompressedPublicKey(first, publicKey.slice(1, 33), publicKey.slice(33, 65));
    default:
      return null;
  }
}

exports.verify = function(message, signature, publicKey) {
  var sigObj = { r: signature.slice(0, 32), s: signature.slice(32, 64) }

  var sigr = new BN(sigObj.r)
  var sigs = new BN(sigObj.s)
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) throw new Error("Bad signature");
  if (sigs.cmp(ec.nh) === 1 || sigr.isZero() || sigs.isZero()) return false;

  var pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error("Parse public key fail");

  return ec.verify(message, sigObj, { x: pair.pub.x, y: pair.pub.y });
};
