const test = require("tape");
const { ffModInverse, Order, ffMul } = require("../dist");

test("ffModInverse", function (t) {
  t.plan(1);
  const a = BigInt(1);
  const b = ffModInverse(a, Order);
  const c = ffMul(a, b);
  t.equal(c, 1n, 'mod inverse works correctly');
});
