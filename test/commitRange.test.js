const test = require("tape");
const { proveComRange, randomValue, G, H, verifyComRangeProof } = require("../dist");
const { commit } = require("../dist/commitment");
const { verifyBinary } = require("../dist/rangeProofs/commitRange");
const { respondBinary } = require("../dist/rangeProofs/commitRange");
const { commitBinary } = require("../dist/rangeProofs/commitRange");

test("comRange Prove", function (t) {
  t.plan(1);
  const r = randomValue();
  console.time('prove ComRange');
  const proof = proveComRange(BigInt(0), r, H, G, 32);
  console.timeEnd('prove ComRange');
  const res = verifyComRangeProof(proof);
  t.equal(res, true, 'ComRangeProof works correctly');
});

test("binary proof", function (t) {
  t.plan(1);
  const b = BigInt(1);
  const r = randomValue();
  const A = commit(b, r, H, G);
  const { Ca, Cb, a, s, t: ti } = commitBinary(b, H, G);
  const c = randomValue();
  const { f, za, zb } = respondBinary(b, r, a, s, ti, c);
  const res = verifyBinary(A, Ca, Cb, H, G, f, za, zb, c);
  t.test();
});
