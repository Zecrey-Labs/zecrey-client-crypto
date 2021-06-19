const test = require("tape");

const {
    randomValue,
    elgamalEnc,
    genKeyPair,
    addStatement,
    newPTransferProofRelation,
    provePTransfer,
    verifyPTransferProof,
    commitValidEnc,
    respondValidEnc,
    verifyValidEnc,
    G, H
} = require("../dist");

test("privacy transfer proof", function (t) {
    t.plan(1);
    const {sk: sk1, pk: pk1} = genKeyPair();
    const b1 = BigInt(8);
    const r1 = randomValue();
    const {sk: sk2, pk: pk2} = genKeyPair();
    const b2 = BigInt(2);
    const r2 = randomValue();
    const {sk: sk3, pk: pk3} = genKeyPair();
    const b3 = BigInt(3);
    const r3 = randomValue();
    const b1Enc = elgamalEnc(b1, r1, pk1);
    const b2Enc = elgamalEnc(b2, r2, pk2);
    const b3Enc = elgamalEnc(b3, r3, pk3);
    var relation = newPTransferProofRelation(1);
    relation = addStatement(relation, b1Enc, pk1, b1, BigInt(-4), sk1);
    relation = addStatement(relation, b2Enc, pk2, undefined, BigInt(1), undefined);
    relation = addStatement(relation, b3Enc, pk3, undefined, BigInt(3), undefined);
    console.time('prove transfer')
    const proof = provePTransfer(relation);
    console.timeEnd('prove transfer')
    const res = verifyPTransferProof(proof);
    t.equal(res, true, 'ptransfer proof works correctly');
});


// test("validEnc Proof", function (t) {
//     t.plan(1);
//     const {sk: sk1, pk: pk1} = genKeyPair();
//     const b1 = BigInt(8);
//     const r1 = randomValue();
//     const b1Enc = elgamalEnc(b1, r1, pk1);
//     const {
//         alpha_r,
//         alpha_bDelta,
//         A_CLDelta,
//         A_CRDelta,
//     } = commitValidEnc(pk1, G, H);
//     const bDelta = BigInt(-3);
//     const CDelta = elgamalEnc(bDelta, r1, pk1);
//     const c = randomValue();
//     const {z_r, z_bDelta} = respondValidEnc(r1, bDelta, alpha_r, alpha_bDelta, c);
//     const ve = verifyValidEnc(pk1, CDelta.CL, A_CLDelta, G, H, CDelta.CR, A_CRDelta, c, z_r, z_bDelta);
//     console.log('ve:', ve)
//     t.test();
// });
