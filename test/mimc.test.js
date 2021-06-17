const test = require("tape");
const { mimcHash } = require("../dist");

test("mimc", function (t) {
  t.plan(1);
  const h = mimcHash(Buffer.from('a'));
  t.equal(h, 88925539951727082148152754576265106003333974681801563312508992897773113270n, 'mimc hash works correctly');
});
