const test = require("tape");
const { genKeyPair, elgamalEnc, elgamalDec, randomValue } = require("../dist");

test("ElGamal Encryption & Decryption", function (t) {
  t.plan(1);
  const { sk, pk } = genKeyPair();
  const Max = BigInt(1000000);
  const b = BigInt(10);
  const r = randomValue();
  console.time('enc');
  const enc = elgamalEnc(b, r, pk);
  console.timeEnd('enc');
  console.time('dec');
  const bprime = elgamalDec(enc, sk, Max);
  console.timeEnd('dec');
  t.equal(bprime, b, 'ElGamal works correctly');
});
