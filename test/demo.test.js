const test = require("tape");
const { hello } = require("../dist");

test("basic", function (t) {
  t.plan(1);
  t.equal(hello(), "hello", "return expected result");
});
