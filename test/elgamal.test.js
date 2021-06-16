const test = require("tape");
const { genKeyPair, elgamalEnc, elgamalDec, randomValue } = require("../dist");

test("ElGamal Encryption & Decryption", function (t) {
  t.plan(1);
  const { sk, pk } = genKeyPair();
  const Max = BigInt(10000);
  const b = BigInt(200);
  const r = randomValue();
  const enc = elgamalEnc(b, r, pk);
  const bprime = elgamalDec(enc, sk, Max);
  t.equal(bprime, b, 'ElGamal works correctly');
});
