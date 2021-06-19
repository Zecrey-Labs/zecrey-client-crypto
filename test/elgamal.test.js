const test = require("tape");
const {genKeyPair, elgamalEnc, elgamalDec, randomValue, elgamalEncAdd} = require("../dist");

test("ElGamal Encryption & Decryption", function (t) {
    t.plan(1);
    const {sk, pk} = genKeyPair();
    const Max = BigInt(1000000);
    const b = BigInt(10);
    const bDelta = BigInt(-4);
    const r = randomValue();
    const r2 = randomValue();
    console.time('enc');
    var enc = elgamalEnc(b, r, pk);
    const CDelta = elgamalEnc(bDelta, r2, pk);
    enc = elgamalEncAdd(enc, CDelta);
    console.timeEnd('enc');
    console.time('dec');
    const bprime = elgamalDec(enc, sk, Max);
    console.timeEnd('dec');
    t.equal(bprime, BigInt(6), 'ElGamal works correctly');
});
