const test = require("tape");
const BN = require('bn.js');
const fs = require('fs');
const { ffMod } = require("../dist/ffmath");
const { randomValue, zeroPoint, newPoint, Order, addPoint, equal, negPoint, scalarHMul, scalarGMul, G, H, marshalPoint, unmarshalPoint, scalarMul, Scalar } = require("../dist/ecc/tebn254");

test("randomValue", function (t) {
    t.plan(1);
    t.test(randomValue());
});

test("ZeroAddAnotherPoint", function (t) {
    t.plan(1);
    const O = zeroPoint();
    const G = newPoint('9671717474070082183213120605117400219616337014328744928644933853176787189663', '16950150798460657717958625567821834550301663161624707787222815936182638968203');
    t.equal(equal(addPoint(O, G), G), true, 'return expected zeroAddAnotherPoint result');
});

test("addPoint", function (t) {
    t.plan(1);
    const a = newPoint('8787197234602503388844295997017788867392848147420327174860413988187367696532', '15305195750036305661220525648961313310481046260814497672243197092298550508693');
    const b = newPoint('5175540365067349569190993754087700847426262666863428620763420610172489480276', '11533909001000295577818857040682494493436124051895563619976413559559984357704');
    const c = newPoint('13163432965829961146207913654929117703936778638068426819932699808929797038169', '12593235468414968750242085888471035041062129592669413010808753916989521208231');
    t.equal(equal(addPoint(a, b), c), true, 'return expected addPoint result');
});

// test("scalarMul", function (t) {
//     t.plan(1);
//     const r1 = BigInt(3);
//     const r2 = BigInt(9);
//     const r3 = BigInt(12);
//     const a = scalarBaseMul(r1);
//     const b = scalarBaseMul(r2);
//     const ab = addPoint(a, b);
//     const c = scalarBaseMul(r3);
//     t.equal(equal(ab, c), true, 'return expected scalarMul result');
// });

test("negPoint", function (t) {
    t.plan(1);
    const G = newPoint('9671717474070082183213120605117400219616337014328744928644933853176787189663', '16950150798460657717958625567821834550301663161624707787222815936182638968203');
    const GNeg = newPoint('12216525397769193039033285140139874868932027386087289415053270333399021305954', G.Y);

    t.equal(equal(negPoint(G), GNeg), true, 'return expected negPoint result');
});

test("marshalPoint", function (t) {
    t.plan(1);
    const G = newPoint('9671717474070082183213120605117400219616337014328744928644933853176787189663', '16950150798460657717958625567821834550301663161624707787222815936182638968203');

    const buf = marshalPoint(G);
    const T = unmarshalPoint(buf);
    t.equal(equal(G, T), true, 'marshal works correctly');
});

test("optimizeScalarMul", function (t) {
    t.plan(1);
    // const r = new BN("-348300407859572751224531059670009367222243066181721333720553737811769195386008976808523958246316773613792514408317458283661241884274052776687974869839");
    // const a = r.mod(Order).add(Order).mod(Order);
    // const rprime = Scalar.neg(r);
    // const a = ffMod(rprime, Order);
    // console.log('a:', a)
    t.test();
    // t.equal(equal(R, R2), true, 'hscalar works correctly');
});
