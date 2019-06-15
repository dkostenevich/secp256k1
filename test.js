var expect = require("chai").expect;
var createHash = require("crypto").createHash;
var eccrypto = require("./");

var msg = createHash("sha256").update("test").digest();

var privateKey = Buffer.alloc(32);
privateKey.fill(1);
var publicKeyCompressed = eccrypto.publicKeyCreate(privateKey);

var privateKeyA = Buffer.alloc(32);
privateKeyA.fill(2);

var privateKeyB = Buffer.alloc(32);
privateKeyB.fill(3);

describe("Key conversion", function() {
  it("shouwld allow to convert private key to compressed public", function() {
	expect(Buffer.isBuffer(publicKeyCompressed)).to.be.true;
	expect(publicKeyCompressed.toString("hex")).to.equal("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
  });
});

describe("ECDSA", function() {
  it("should allow to sign and verify message using a compressed public key", function() {
    var sig = eccrypto.sign(msg, privateKey);
    expect(sig.signature.toString("hex")).to.equal("78c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f816e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c");
    return eccrypto.verify(msg, sig.signature, publicKeyCompressed);
  });
});