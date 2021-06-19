import {
    PTransferProof,
    PTransferSubProof,
    PTransferProofRelation,
    PTransferProofStatement,
    TransferCommitValues
} from './transfer.d';
import {ElGamalEnc, elgamalEnc} from '../elgamal';
import {
    randomValue,
    addPoint,
    negPoint,
    scalarMul,
    G,
    H,
    Order,
    Point,
    equal,
    marshalPoint,
    zeroPoint,
    Scalar
} from '../ecc';
import {ffAdd, ffAddMod, ffModInverse, ffMul, ffSubMod} from '../ffmath';
import {commit} from '../commitment';
import {concat, proveComRange, verifyComRangeProof} from "../rangeProofs";
import {mimcHash} from "../hash";


export const newPTransferProofRelation = (tokenId: number): PTransferProofRelation => {
    if (tokenId < 0) {
        throw new Error('err: invalid tokenId');
    }
    var Ht = scalarMul(H, BigInt(tokenId));
    return {G: G, H: H, Order: Order, Ht: Ht, TokenId: tokenId};
}

export const addStatement = (relation: PTransferProofRelation, C: ElGamalEnc, pk: Point, b: BigInt | undefined, bDelta: BigInt, sk: BigInt | undefined): PTransferProofRelation => {
    // check params
    if (C === undefined || pk === undefined) {
        throw new Error('err: invalid params');
    }
    if (relation.Pts === undefined) {
        relation.Pts = [];
    }
    if (relation.Statements === undefined) {
        relation.Statements = [];
    }
    // if the user owns the account, should do more verifications
    if (sk !== undefined) {
        var oriPk = scalarMul(G, sk);
        // 1. should be the same public key
        // 2. b should not be null and larger than zero
        // 3. bDelta should larger than zero
        if (!equal(oriPk, pk)) {
            throw new Error('err: inconsistent public key');
        }
        if (b === undefined || b < BigInt(0)) {
            throw new Error('err: insufficient balance');
        }
        if (bDelta > BigInt(0)) {
            throw new Error('err: invalid bDelta');
        }
        if (relation.Ht === undefined) {
            throw new Error('err: invalid relation');
        }
        // add Pt
        var Pt = scalarMul(relation.Ht, sk);

        relation.Pts.push(Pt);
    }
    // now b != nil
    // if user knows b which means that he owns the account
    var bStar: BigInt = BigInt(0);
    if (b !== undefined) {
        // b' = b + b^{\Delta}
        var bPrime = ffAdd(b, bDelta);
        // bPrime should bigger than zero
        if (bPrime < BigInt(0)) {
            throw new Error('err: insufficient balance');
        }
        bStar = bPrime;
    } else {
        bStar = bDelta;
        bPrime = BigInt(0);
    }
    // r \gets_R \mathbb{Z}_p
    var r: BigInt = randomValue();
    // C^{\Delta} = (pk^r, g^r h^{b^{\Delta}})
    var CDelta = elgamalEnc(bDelta, r, pk);
    if (CDelta === null) {
        throw new Error('err: invalid encryption');
    }
    // r^{\star} \gets_R \mathbb{Z}_p
    var rStar = randomValue();
    // \bar{r} \gets_R \mathbb{Z}_p
    var rBar = randomValue();
    // T = g^{\bar{r}} h^{b'}
    var T = commit(rBar, bPrime, G, H);
    var Y = commit(rStar, bStar, G, H);
    // create statement
    var statement = {
        // ------------- public ---------------------
        C: C,
        CDelta: CDelta,
        T: T,
        Y: Y,
        Pk: pk,
        TCRprimeInv: addPoint(T, negPoint(addPoint(C.CR, CDelta.CR))),
        CLprimeInv: negPoint(addPoint(C.CL, CDelta.CL)),
        // ----------- private ---------------------
        BDelta: bDelta,
        BStar: bStar,
        BPrime: bPrime,
        Sk: sk,
        R: r,
        RBar: rBar,
        RStar: rStar,
    };
    // @ts-ignore
    relation.Statements.push(statement);
    return relation;
}

export const provePTransfer = (relation: PTransferProofRelation): PTransferProof => {
    if (relation === undefined || relation.Statements == undefined) {
        throw new Error('err: invalid params');
    }
    // verify \sum b_i^{\Delta} = 0
    var sum: BigInt = BigInt(0);
    for (var i = 0; i < relation.Statements.length; i++) {
        var statement = relation.Statements[i];
        sum = ffAdd(sum, statement.BDelta);
    }
    // statements must be correct
    if (sum !== BigInt(0)) {
        throw new Error('err: invalid transfer amounts');
    }

    // initialize proof
    // @ts-ignore
    var proof: PTransferProof = {};
    proof.SubProofs = [];
    proof.A_Pts = [];
    proof.Z_tsks = [];
    // add Pts,G,Waste from relation
    // @ts-ignore
    proof.Pts = relation.Pts
    proof.G = relation.G
    proof.H = relation.H
    // @ts-ignore
    proof.Ht = relation.Ht
    // write public statements into buf
    var buf = Buffer.from('');
    buf = concat(buf, marshalPoint(proof.G));
    buf = concat(buf, marshalPoint(proof.H));
    buf = concat(buf, marshalPoint(proof.Ht));
    // commit phase
    const n = relation.Statements.length;
    var commitEntities = new Array<TransferCommitValues>(n);
    var A_sum = zeroPoint();
    // for range proofs
    //secrets = make([]*big.Int, n) // accounts balance
    //gammas = make([]*big.Int, n)  // random values
    //Vs = make([]*Point, n)        // commitments for accounts balance
    for (var i = 0; i < n; i++) {
        const statement = relation.Statements[i];
        // write common inputs into buf
        buf = concat(buf, marshalPoint(statement.C.CL));
        buf = concat(buf, marshalPoint(statement.C.CR));
        buf = concat(buf, marshalPoint(statement.CDelta.CL));
        buf = concat(buf, marshalPoint(statement.CDelta.CR));
        buf = concat(buf, marshalPoint(statement.T));
        buf = concat(buf, marshalPoint(statement.Y));
        buf = concat(buf, marshalPoint(statement.Pk));
        buf = concat(buf, marshalPoint(statement.TCRprimeInv));
        buf = concat(buf, marshalPoint(statement.CLprimeInv));

        // statement values
        var C = statement.C;
        var CDelta = statement.CDelta
        var pk = statement.Pk
        var sk = statement.Sk
        // initialize commit values
        // @ts-ignore
        commitEntities[i] = {}
        // start Sigma protocol
        // commit enc values
        // @ts-ignore
        const {alpha_r, alpha_bDelta, A_CLDelta, A_CRDelta} = commitValidEnc(pk, proof.G, proof.H)
        commitEntities[i].alpha_r = alpha_r;
        commitEntities[i].alpha_bDelta = alpha_bDelta;
        commitEntities[i].A_CLDelta = A_CLDelta;
        commitEntities[i].A_CRDelta = A_CRDelta;
        // prove \sum_{i=1}^n b_i^{\Delta}
        A_sum = addPoint(A_sum, scalarMul(G, commitEntities[i].alpha_bDelta))
        // write into buf
        buf = concat(buf, marshalPoint(commitEntities[i].A_CLDelta));
        buf = concat(buf, marshalPoint(commitEntities[i].A_CRDelta));
        // if user does not own the account, then commit bDelta.
        if (sk === undefined) {
            // @ts-ignore
            const {alpha_rstarSubr, A_YDivCRDelta} = commitValidDelta(G);
            commitEntities[i].alpha_rstarSubr = alpha_rstarSubr;
            commitEntities[i].A_YDivCRDelta = A_YDivCRDelta;
        } else { // Otherwise, commit ownership
            // commit to ownership
            const {
                alpha_rstarSubrbar, alpha_rbar, alpha_bprime, alpha_sk, alpha_skInv,
                A_YDivT, A_T, A_pk, A_TDivCPrime,
            } = commitOwnership(G, H, negPoint(addPoint(C.CL, CDelta.CL))) // commit to tokenId
            commitEntities[i].alpha_rstarSubrbar = alpha_rstarSubrbar;
            commitEntities[i].alpha_rbar = alpha_rbar;
            commitEntities[i].alpha_bprime = alpha_bprime;
            commitEntities[i].alpha_sk = alpha_sk;
            commitEntities[i].alpha_skInv = alpha_skInv;
            commitEntities[i].A_YDivT = A_YDivT;
            commitEntities[i].A_T = A_T;
            // @ts-ignore
            commitEntities[i].A_pk = A_pk;
            commitEntities[i].A_TDivCPrime = A_TDivCPrime
        }
        // generate sub proofs
        var commitValues = commitEntities[i];
        var secrets = [];
        var gammas = [];
        var Vs = [];
        proof.SubProofs.push(
            // @ts-ignore
            {
                A_CLDelta: commitValues.A_CLDelta,
                A_CRDelta: commitValues.A_CRDelta,
                A_YDivCRDelta: commitValues.A_YDivCRDelta,
                A_YDivT: commitValues.A_YDivT,
                A_T: commitValues.A_T,
                A_pk:
                commitValues.A_pk,
                A_TDivCPrime: commitValues.A_TDivCPrime,
                // original balance enc
                C: statement.C,
                // delta balance enc
                CDelta: statement.CDelta,
                // new pedersen commitment for new balance
                T: statement.T,
                // new pedersen commitment for deleta balance or new balance
                Y: statement.Y,
                // public key
                Pk: statement.Pk,
                // T (C_R + C_R^{\Delta})^{-1}
                TCRprimeInv: statement.TCRprimeInv,
                // (C_L + C_L^{\Delta})^{-1}
                CLprimeInv: statement.CLprimeInv,
            }
        );
        // complete range proof statements
        secrets.push(statement.BStar)
        gammas.push(statement.RStar)
        Vs.push(statement.Y)
    }
    // set A_sum
    proof.A_sum = A_sum
    // make sure the length of commitEntities and statements is equal
    if (commitEntities.length !== relation.Statements.length) {
        throw new Error('err: invalid statements');
    }
    // challenge phase
    var c = mimcHash(buf);
    // random challenge for sim
    var c1 = randomValue();
    var c2 = Scalar.bxor(c, c1);
    proof.C1 = c1
    proof.C2 = c2
    for (var i = 0; i < commitEntities.length; i++) {
        // get values first
        var commitValues = commitEntities[i];
        var statement = relation.Statements[i];
        var {z_r, z_bDelta} = respondValidEnc(
            statement.R, statement.BDelta, commitValues.alpha_r, commitValues.alpha_bDelta, c,
        );
        // if the user does not own the account, run simOwnership
        if (statement.Sk === undefined && commitValues.alpha_rstarSubr !== undefined) {
            var z_rstarSubr = respondValidDelta(
                ffSubMod(statement.RStar, statement.R, Order),
                commitValues.alpha_rstarSubr, c1,
            );
            var {
                A_YDivT, A_T, A_pk, A_TDivCPrime,
                z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv
            }
                = simOwnership(
                G, H, statement.Y, statement.T, statement.Pk,
                statement.TCRprimeInv, statement.CLprimeInv,
                c2,
            );
            // complete sub proofs
            proof.SubProofs[i].Z_rstarSubr = z_rstarSubr;
            // @ts-ignore
            proof.SubProofs[i].A_YDivT = A_YDivT;
            // @ts-ignore
            proof.SubProofs[i].A_T = A_T;
            // @ts-ignore
            proof.SubProofs[i].A_pk = A_pk;
            // @ts-ignore
            proof.SubProofs[i].A_TDivCPrime = A_TDivCPrime;
            // @ts-ignore
            proof.SubProofs[i].Z_rstarSubrbar = z_rstarSubrbar;
            // @ts-ignore
            proof.SubProofs[i].Z_rbar = z_rbar;
            // @ts-ignore
            proof.SubProofs[i].Z_bprime = z_bprime;
            // @ts-ignore
            proof.SubProofs[i].Z_sk = z_sk;
            // @ts-ignore
            proof.SubProofs[i].Z_skInv = z_skInv
        } else { // otherwise, run simValidDelta
            // @ts-ignore
            var {A_YDivCRDelta, z_rstarSubr} = simValidDelta(
                statement.CDelta.CR, statement.Y, G,
                c1,
            );
            // @ts-ignore
            var {z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv} = respondOwnership(
                ffSubMod(statement.RStar, statement.RBar, Order),
                statement.RBar, statement.BPrime, statement.Sk,
                commitValues.alpha_rstarSubrbar, commitValues.alpha_rbar,
                commitValues.alpha_bprime, commitValues.alpha_sk, commitValues.alpha_skInv, c2,
            );
            // complete sub proofs
            // @ts-ignore
            proof.SubProofs[i].A_YDivCRDelta = A_YDivCRDelta;
            proof.SubProofs[i].Z_rstarSubr = z_rstarSubr;
            // @ts-ignore
            proof.SubProofs[i].Z_rstarSubrbar = z_rstarSubrbar;
            // @ts-ignore
            proof.SubProofs[i].Z_rbar = z_rbar;
            // @ts-ignore
            proof.SubProofs[i].Z_bprime = z_bprime;
            // @ts-ignore
            proof.SubProofs[i].Z_sk = z_sk;
            // @ts-ignore
            proof.SubProofs[i].Z_skInv = z_skInv;
            // commit to Pt = Ht^{sk}
            // @ts-ignore
            var {A_Pt, z_tsk} = provePt(undefined, statement.Sk, relation.Ht, c);
            // @ts-ignore
            proof.A_Pts.push(A_Pt);
            // @ts-ignore
            proof.Z_tsks.push(z_tsk);
        }
        // compute the range proof
        var rangeProof = proveComRange(statement.BStar, statement.RStar, H, G, 32);
        // set the range proof into sub proofs
        proof.SubProofs[i].CRangeProof = rangeProof;
        // complete sub proofs
        // @ts-ignore
        proof.SubProofs[i].Z_r = z_r;
        // @ts-ignore
        proof.SubProofs[i].Z_bDelta = z_bDelta;
    }
    // @ts-ignore
    var slen = secrets.length;
    // @ts-ignore
    var glen = gammas.length
    // @ts-ignore
    var Vlen = Vs.length;
    if (slen !== glen || slen !== Vlen) {
        throw new Error('err: invalid range params');
    }
    // response phase
    return proof;
}

export const
    verifyPTransferProof = (proof: PTransferProof): boolean => {
        // generate the challenge
        var buf = Buffer.from('');
        buf = concat(buf, marshalPoint(proof.G));
        buf = concat(buf, marshalPoint(proof.H));
        buf = concat(buf, marshalPoint(proof.Ht));
        for (var i = 0; i < proof.SubProofs.length; i++) {
            const subProof = proof.SubProofs[i];
            // write common inputs into buf
            buf = concat(buf, marshalPoint(subProof.C.CL));
            buf = concat(buf, marshalPoint(subProof.C.CR));
            buf = concat(buf, marshalPoint(subProof.CDelta.CL));
            buf = concat(buf, marshalPoint(subProof.CDelta.CR));
            buf = concat(buf, marshalPoint(subProof.T));
            buf = concat(buf, marshalPoint(subProof.Y));
            buf = concat(buf, marshalPoint(subProof.Pk));
            buf = concat(buf, marshalPoint(subProof.TCRprimeInv));
            buf = concat(buf, marshalPoint(subProof.CLprimeInv));
            buf = concat(buf, marshalPoint(subProof.A_CLDelta));
            buf = concat(buf, marshalPoint(subProof.A_CRDelta));
        }
        // c = hash()
        var c = mimcHash(buf);
        // verify c
        var cCheck = Scalar.bxor(proof.C1, proof.C2);
        if (c !== cCheck) {
            throw new Error('err: invalid challenge');
        }
        // verify Pt proof
        if (proof.Pts.length !== proof.A_Pts.length || proof.Pts.length !== proof.Z_tsks.length) {
            throw new Error('err: invalid params');
        }
        for (var i = 0; i < proof.Pts.length; i++) {
            var l = scalarMul(proof.Ht, proof.Z_tsks[i]);
            var r = addPoint(proof.A_Pts[i], scalarMul(proof.Pts[i], c));
            if (!equal(l, r)) {
                console.log('111')
                return false;
            }
        }
        var g = proof.G
        var h = proof.H
        // verify sub proofs
        var lSum = zeroPoint();
        for (var i = 0; i < proof.SubProofs.length; i++) {
            const subProof = proof.SubProofs[i];
            // verify range proof
            var rangeRes = verifyComRangeProof(subProof.CRangeProof);
            if (!rangeRes) {
                return false;
            }
            // verify valid enc
            var validEncRes = verifyValidEnc(
                subProof.Pk, subProof.CDelta.CL, subProof.A_CLDelta, g, h, subProof.CDelta.CR, subProof.A_CRDelta,
                c,
                subProof.Z_r, subProof.Z_bDelta,
            );
            if (!validEncRes) {
                console.log('222')
                return false;
            }
            var YDivCRDelta = addPoint(subProof.Y, negPoint(subProof.CDelta.CR))
            // verify valid Delta
            var validDeltaRes = verifyValidDelta(
                g, YDivCRDelta, subProof.A_YDivCRDelta,
                proof.C1,
                subProof.Z_rstarSubr,
            );
            if (!validDeltaRes) {
                console.log('333')
                return false;
            }
            var YDivT = addPoint(subProof.Y, negPoint(subProof.T))
            // verify ownership
            var ownershipRes = verifyOwnership(
                g, YDivT, subProof.A_YDivT, h, subProof.T, subProof.A_T, subProof.Pk, subProof.A_pk,
                subProof.CLprimeInv, subProof.TCRprimeInv, subProof.A_TDivCPrime,
                proof.C2,
                subProof.Z_rstarSubrbar, subProof.Z_rbar,
                subProof.Z_bprime, subProof.Z_sk, subProof.Z_skInv,
            );
            if (!ownershipRes) {
                console.log('444')
                return false;
            }
            // set z_bDeltas for sum proof
            lSum = addPoint(lSum, scalarMul(g, subProof.Z_bDelta))
        }

        // verify sum proof
        var rSum = proof.A_sum
        return equal(lSum, rSum);
    }

/*
 commit phase for R_{ValidDelta} = {Y/C_R^{\Delta} = g^{r^{\star} - r}}
 @g: generator
 */
export const
    commitValidDelta = (g: Point): { alpha_rstarSubr: BigInt, A_YDivCRDelta: Point } => {
        var alpha_rstarSubr = randomValue();
        var A_YDivCRDelta = scalarMul(g, alpha_rstarSubr);
        return {alpha_rstarSubr: alpha_rstarSubr, A_YDivCRDelta: A_YDivCRDelta};
    }

export const
    respondValidDelta = (rstarSubr: BigInt, alpha_rstarSubr: BigInt, c: BigInt): BigInt => {
        var z_rstarSubr = ffAddMod(alpha_rstarSubr, ffMul(c, rstarSubr), Order)
        return z_rstarSubr;
    }

/*
	verifyValidDelta verifys the delta proof
	@g: the generator
	@YDivCRDelta: public inputs
	@A_YDivCRDelta: the random commitment
	@c: the challenge
	@z_rstarSubr: response values for valid delta proof
*/
export const
    verifyValidDelta = (
        g: Point, YDivCRDelta: Point, A_YDivCRDelta: Point,
        c: BigInt,
        z_rstarSubr: BigInt,
    ): boolean => {
        // g^{z_r^{\star}} == A_{Y/(C_R^{\Delta})} [Y/(C_R^{\Delta})]^c
        var l = scalarMul(g, z_rstarSubr);
        var r = addPoint(A_YDivCRDelta, scalarMul(YDivCRDelta, c));
        return equal(l, r);
    }

export const
    simValidDelta = (
        C_RDelta: Point, Y: Point, g: Point, cSim: BigInt,
    ): {
        A_YDivCRDelta: Point, z_rstarSubr: BigInt,
    } => {
        var z_rstarSubr = randomValue();
        var A_YDivCRDelta = addPoint(
            scalarMul(g, z_rstarSubr),
            scalarMul(negPoint(addPoint(Y, negPoint(C_RDelta))), cSim),
        )
        return {A_YDivCRDelta: A_YDivCRDelta, z_rstarSubr: z_rstarSubr};
    }

/*
 commit phase for R_{Ownership} = {
Y/T = g^{r^{\star} - \bar{r}} \wedge
T = g^{\bar{r}} h^{b'} \wedge
pk = g^{sk} \wedge
T(C_R + C_R^{\Delta})^{-1} = [(C_L + C_L^{\Delta})^{-1}]^{sk^{-1}} g^{\bar{r}} \wedge}
 @g: generator
 @h: generator
 @hDec: (C_L + C_L^{\Delta})^{-1}
 */
export const
    commitOwnership = (g: Point, h: Point, hDec: Point): {
        alpha_rstarSubrbar: BigInt, alpha_rbar: BigInt, alpha_bprime: BigInt, alpha_sk: BigInt, alpha_skInv: BigInt,
        A_YDivT: Point, A_T: Point, A_pk: Point, A_TDivCPrime: Point,
    } => {
        var alpha_rstarSubrbar = randomValue();
        var alpha_rbar = randomValue();
        var alpha_bprime = randomValue();
        var alpha_sk = randomValue();
        var alpha_skInv = ffModInverse(alpha_sk, Order);
        var A_YDivT = scalarMul(g, alpha_rstarSubrbar)
        var A_T = addPoint(scalarMul(g, alpha_rbar), scalarMul(h, alpha_bprime));
        var A_pk = scalarMul(g, alpha_sk);
        var A_TDivCPrime = addPoint(scalarMul(hDec, alpha_skInv), scalarMul(g, alpha_rbar));
        return {
            alpha_rstarSubrbar: alpha_rstarSubrbar,
            alpha_rbar: alpha_rbar,
            alpha_bprime: alpha_bprime,
            alpha_sk: alpha_sk,
            alpha_skInv: alpha_skInv,
            A_YDivT: A_YDivT,
            A_T: A_T,
            A_pk: A_pk,
            A_TDivCPrime: A_TDivCPrime,
        };
    }

export const
    respondOwnership = (
        rstarSubrbar: BigInt, rbar: BigInt, bprime: BigInt, sk: BigInt,
        alpha_rstarSubrbar: BigInt, alpha_rbar: BigInt, alpha_bprime: BigInt, alpha_sk: BigInt, alpha_skInv: BigInt, c: BigInt,
    ):
        {
            z_rstarSubrbar: BigInt, z_rbar: BigInt, z_bprime: BigInt, z_sk: BigInt, z_skInv: BigInt,
        } => {
        var z_rstarSubrbar = ffAddMod(alpha_rstarSubrbar, ffMul(c, rstarSubrbar), Order);
        var z_rbar = ffAddMod(alpha_rbar, ffMul(c, rbar), Order);
        var z_bprime = ffAddMod(alpha_bprime, ffMul(c, bprime), Order);
        var skInv = ffModInverse(sk, Order);
        var z_sk = ffAddMod(alpha_sk, ffMul(c, sk), Order);
        var z_skInv = ffAddMod(alpha_skInv, ffMul(c, skInv), Order);
        return {z_rstarSubrbar: z_rstarSubrbar, z_rbar: z_rbar, z_bprime: z_bprime, z_sk: z_sk, z_skInv: z_skInv};
    }

/*
	verifyOwnership verifys the ownership of the account
	@YDivT,T,pk,CLprimeInv,TCRprimeInv: public inputs
	@A_YDivT,A_T,A_pk,A_TCRprimeInv: random commitments
	@g,h: generators
	@c: the challenge
	@z_rstarSubrbar, z_rbar, z_bprime, z_sk, z_skInv: response values for valid delta proof
*/
export const
    verifyOwnership = (
        g: Point, YDivT: Point, A_YDivT: Point, h: Point, T: Point, A_T: Point, pk: Point, A_pk: Point, CLprimeInv: Point, TCRprimeInv: Point, A_TCRprimeInv: Point,
        c: BigInt,
        z_rstarSubrbar: BigInt, z_rbar: BigInt, z_bprime: BigInt, z_sk: BigInt, z_skInv: BigInt,
    ): boolean => {
        // verify Y/T = g^{r^{\star} - \bar{r}}
        var l1 = scalarMul(g, z_rstarSubrbar);
        var r1 = addPoint(A_YDivT, scalarMul(YDivT, c));
        if (!equal(l1, r1)) {
            return false;
        }
        // verify T = g^{\bar{r}} h^{b'}
        var gzrbar = scalarMul(g, z_rbar);
        var l2 = addPoint(gzrbar, scalarMul(h, z_bprime));
        var r2 = addPoint(A_T, scalarMul(T, c));
        if (!equal(l2, r2)) {
            return false;
        }
        // verify pk = g^{sk}
        var l3 = scalarMul(g, z_sk);
        var r3 = addPoint(A_pk, scalarMul(pk, c));
        if (!equal(l3, r3)) {
            return false;
        }
        // verify T(C'_R)^{-1} = (C'_L)^{-sk^{-1}} g^{\bar{r}}
        var l4 = addPoint(gzrbar, scalarMul(CLprimeInv, z_skInv));
        var r4 = addPoint(A_TCRprimeInv, scalarMul(TCRprimeInv, c));
        return equal(l4, r4);
    }

export const simOwnership = (
    g: Point, h: Point, Y: Point, T: Point, pk: Point, TCRprimeInv: Point, CLprimeInv: Point,
    cSim: BigInt,
): {
    A_YDivT: Point, A_T: Point, A_pk: Point, A_TDivCPrime: Point,
    z_rstarSubrbar: BigInt, z_rbar: BigInt, z_bprime: BigInt, z_sk: BigInt, z_skInv: BigInt,
} => {
    var z_rstarSubrbar = randomValue();
    var z_rbar = randomValue();
    var z_bprime = randomValue();
    var z_sk = randomValue();
    var z_skInv = randomValue();
    // A_{Y/T} = g^{z_{r^{\star} - \bar{r}}} (Y T^{-1})^{-c}
    var A_YDivT = addPoint(
        scalarMul(g, z_rstarSubrbar),
        scalarMul(negPoint(addPoint(Y, negPoint(T))), cSim),
    );
    // A_T = g^{z_{\bar{r}}} h^{z_{b'}} (T)^{-c}
    var A_T = addPoint(
        addPoint(scalarMul(g, z_rbar), scalarMul(h, z_bprime)),
        scalarMul(negPoint(T), cSim),
    );
    // A_{pk} = g^{z_{sk}} pk^{-c}
    var A_pk = addPoint(
        scalarMul(g, z_sk),
        scalarMul(negPoint(pk), cSim),
    );
    // A_{T(C_R + C_R^{\Delta})^{-1}} =
    // g^{z_{\bar{r}}} [(C_L + C_L^{\Delta})^{-1}]^{z_{skInv}} [T(C_R + C_R^{\Delta})^{-1}]^{-c}
    var A_TDivCPrime = addPoint(
        addPoint(scalarMul(g, z_rbar), scalarMul(CLprimeInv, z_skInv)),
        scalarMul(negPoint(TCRprimeInv), cSim),
    )
    return {
        A_YDivT: A_YDivT, A_T: A_T, A_pk: A_pk, A_TDivCPrime: A_TDivCPrime,
        z_rstarSubrbar: z_rstarSubrbar, z_rbar: z_rbar, z_bprime: z_bprime, z_sk: z_sk, z_skInv: z_skInv
    };
}


/**
 commit phase for R_{ValidEnc} = {C_L = pk^r \wedge C_R = g^r h^{b}}
 @pk: public key
 @g: generator
 @h: generator
 */
export const
    commitValidEnc = (pk: Point, g: Point, h: Point): {
        alpha_r: BigInt, alpha_bDelta: BigInt, A_CLDelta: Point, A_CRDelta: Point,
    } => {
        var alpha_r = randomValue();
        var alpha_bDelta = randomValue();
        var A_CLDelta = scalarMul(pk, alpha_r);
        var A_CRDelta = addPoint(scalarMul(g, alpha_r), scalarMul(h, alpha_bDelta));
        return {alpha_r: alpha_r, alpha_bDelta: alpha_bDelta, A_CLDelta: A_CLDelta, A_CRDelta: A_CRDelta};
    }

export const
    respondValidEnc = (r: BigInt, bDelta: BigInt, alpha_r: BigInt, alpha_bDelta: BigInt, c: BigInt): {
        z_r: BigInt, z_bDelta: BigInt,
    } => {
        var z_r = ffAddMod(alpha_r, ffMul(c, r), Order);
        var z_bDelta = ffAddMod(alpha_bDelta, ffMul(c, bDelta), Order);
        return {z_r: z_r, z_bDelta: z_bDelta};
    }

/*
	verifyValidEnc verifys the encryption
	@pk: the public key for the encryption
	@C_LDelta,C_RDelta: parts for the encryption
	@A_C_LDelta,A_CRDelta: random commitments
	@h: the generator
	@c: the challenge
	@z_r,z_bDelta: response values for valid enc proof
*/
export const
    verifyValidEnc = (
        pk: Point, C_LDelta: Point, A_CLDelta: Point, g: Point, h: Point, C_RDelta: Point, A_CRDelta: Point,
        c: BigInt,
        z_r: BigInt, z_bDelta: BigInt,
    ): boolean => {
        // pk^{z_r} == A_{C_L^{\Delta}} (C_L^{\Delta})^c
        var l1 = scalarMul(pk, z_r);
        var r1 = addPoint(A_CLDelta, scalarMul(C_LDelta, c));
        if (!equal(l1, r1)) {
            return false;
        }
        // g^{z_r} h^{z_b^{\Delta}} == A_{C_R^{\Delta}} (C_R^{\Delta})^c
        var l2 = addPoint(scalarMul(g, z_r), scalarMul(h, z_bDelta));
        var r2 = addPoint(A_CRDelta, scalarMul(C_RDelta, c));
        return equal(l2, r2);
    }

export const provePt = (alpha_zsk: BigInt | undefined, sk: BigInt, Ht: Point, c: BigInt): {
    A_Pt: Point, z_tsk: BigInt,
} => {
    if (alpha_zsk == undefined) {
        alpha_zsk = randomValue();
    }
    var A_Pt = scalarMul(Ht, alpha_zsk);
    var z_tsk = ffAddMod(alpha_zsk, ffMul(c, sk), Order)
    return {A_Pt: A_Pt, z_tsk: z_tsk};
}

export const verifyPt = (
    Ht: Point, Pt: Point, A_Pt: Point,
    c: BigInt,
    z_tsk: BigInt,
): boolean => {
    var l = scalarMul(Ht, z_tsk);
    var r = addPoint(A_Pt, scalarMul(Pt, c));
    return equal(l, r);
}
