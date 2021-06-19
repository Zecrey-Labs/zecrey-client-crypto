import {Point, randomValue, Order, addPoint, scalarMul, equal, marshalPoint, zeroPoint} from '../ecc';
import {commit} from '../commitment';
import {ffMul, ffAddMod, ffSub, ffAdd, ffMod} from '../ffmath';
import {toBinary, powerOfVec} from './utils';
import {mimcHash} from '../hash';

export interface ComRangeProof {
    // binary proof
    Cas?: Point[],
    Cbs?: Point[],
    Fs?: BigInt[],
    Zas?: BigInt[],
    Zbs?: BigInt[],
    // same commitment proof
    Zb?: BigInt,
    Zr?: BigInt,
    Zrprime?: BigInt,
    A_T?: Point,
    A_Tprime?: Point,
    // public statements
    T?: Point,
    Tprime?: Point,
    G?: Point,
    H?: Point,
    As?: Point[],
}

export const concat = (a: Buffer, b: Buffer): Buffer => {
    const c = Buffer.concat([a, b]);
    return c;
}

/*
    prove the value in the range
    @b: the secret value
    @r: the random value
    @g,h: two generators
*/
export const proveComRange = (b: BigInt, r: BigInt, g: Point, h: Point, N: number): ComRangeProof => {
    // check params
    if (b < BigInt(0)) {
        throw new Error('err: b should larger than 0');
    }
    // create a new proof
    const proof: ComRangeProof = {};
    proof.G = g;
    proof.H = h;
    proof.As = new Array<Point>(N);
    proof.Cas = new Array<Point>(N);
    proof.Cbs = new Array<Point>(N);
    proof.Fs = new Array<BigInt>(N);
    proof.Zas = new Array<BigInt>(N);
    proof.Zbs = new Array<BigInt>(N);
    // buf to compute the challenge
    var buf: Buffer = Buffer.from('');
    const gMarshal = marshalPoint(g);
    const hMarshal = marshalPoint(h);
    buf = concat(buf, gMarshal);
    buf = concat(buf, hMarshal);
    // commitment to the value
    const T = commit(b, r, g, h);
    // set proof
    proof.T = T
    const TMarshal = marshalPoint(T);
    buf = concat(buf, TMarshal);
    // convert the value into binary
    const bsInt = toBinary(b, N);
    // get power of 2 vec
    const powerof2Vec = powerOfVec(BigInt(2), N);
    // compute T' = \prod_{i=0}^{31}(A_i)^{2^i}
    var Tprime = zeroPoint();
    // compute A_i = g^{b_i} h^{r_i}
    const rs = new Array<BigInt>(N);
    const as = new Array<BigInt>(N);
    const ss = new Array<BigInt>(N);
    const ts = new Array<BigInt>(N);
    // r' = \sum_{i=0}^{31} 2^i r_i
    var rprime: BigInt = BigInt(0);
    for (var i = 0; i < bsInt.length; i++) {
        const bi = bsInt[i];
        // r_i \gets_R \mathbb{Z}_p
        const ri = randomValue();
        // compute A_i
        const Ai = commit(bi, ri, g, h);
        const AiMarshal = marshalPoint(Ai);
        buf = concat(buf, AiMarshal);
        // commitBinary to A_i
        const {Ca: Cai, Cb: Cbi, a: ai, s: si, t: ti} = commitBinary(bi, g, h);
        const CaiMarshal = marshalPoint(Cai);
        const CbiMarshal = marshalPoint(Cbi);
        buf = concat(buf, CaiMarshal);
        buf = concat(buf, CbiMarshal);
        // update T'
        Tprime = addPoint(Tprime, scalarMul(Ai, powerof2Vec[i]));
        // set proof
        proof.As[i] = Ai;
        proof.Cas[i] = Cai;
        proof.Cbs[i] = Cbi;
        // set values
        rs[i] = ri;
        as[i] = ai;
        ss[i] = si;
        ts[i] = ti;
        rprime = ffAdd(rprime, ffMul(ri, powerof2Vec[i]));
    }
    rprime = ffMod(rprime, Order);
    // prove T,T'
    const {
        A_T: A_T,
        A_Tprime: A_Tprime,
        alpha_b: alpha_b,
        alpha_r: alpha_r,
        alpha_rprime: alpha_rprime
    } = commitCommitmentSameValue(g, h);
    // write into buf
    const A_TMarshal = marshalPoint(A_T);
    const A_TprimeMarshal = marshalPoint(A_Tprime);
    buf = concat(buf, A_TMarshal);
    buf = concat(buf, A_TprimeMarshal);
    // compute the challenge
    const c = mimcHash(buf);
    // prove same value commitment
    const {
        zb: zb,
        zr: zr,
        zrprime: zrprime
    } = respondCommitmentSameValue(b, r, rprime, alpha_b, alpha_r, alpha_rprime, c);
    // set proof
    proof.Tprime = Tprime;
    proof.A_T = A_T;
    proof.A_Tprime = A_Tprime;
    proof.Zb = zb;
    proof.Zr = zr;
    proof.Zrprime = zrprime;
    // prove binary
    for (var i = 0; i < bsInt.length; i++) {
        const bi = bsInt[i];
        const {f: fi, za: zai, zb: zbi} = respondBinary(bi, rs[i], as[i], ss[i], ts[i], c);
        proof.Fs[i] = fi;
        proof.Zas[i] = zai;
        proof.Zbs[i] = zbi;
    }
    return proof
}

/*
    Verify a CommitmentRangeProof
*/
export const verifyComRangeProof = (proof: ComRangeProof): boolean => {
    if (proof.Cas === undefined ||
        proof.Cbs === undefined ||
        proof.Fs === undefined ||
        proof.Zas === undefined ||
        proof.Zbs === undefined ||
        proof.Zb === undefined ||
        proof.Zr === undefined ||
        proof.Zrprime === undefined ||
        proof.A_T === undefined ||
        proof.A_Tprime === undefined ||
        proof.Tprime === undefined ||
        proof.T === undefined ||
        proof.G === undefined ||
        proof.H === undefined ||
        proof.As === undefined) {
        throw new Error('err: invalid proof');
    }
    // reconstruct buf
    // buf to compute the challenge
    var buf: Buffer = Buffer.from('');
    // var buf bytes.Buffer
    const GMarshal = marshalPoint(proof.G);
    const HMarshal = marshalPoint(proof.H);
    const TMarshal = marshalPoint(proof.T);
    buf = concat(buf, GMarshal);
    buf = concat(buf, HMarshal);
    buf = concat(buf, TMarshal);
    // set buf and
    // check if T' = (A_i)^{2^i}
    const powerof2Vec = powerOfVec(BigInt(2), proof.As.length);
    var Tprime_check = zeroPoint();
    for (var i = 0; i < proof.As.length; i++) {
        const Ai = proof.As[i];
        const AiMarshal = marshalPoint(Ai);
        const CaiMarshal = marshalPoint(proof.Cas[i]);
        const CbiMarshal = marshalPoint(proof.Cbs[i]);
        buf = concat(buf, AiMarshal);
        buf = concat(buf, CaiMarshal);
        buf = concat(buf, CbiMarshal);
        Tprime_check = addPoint(Tprime_check, scalarMul(Ai, powerof2Vec[i]));
    }
    // check sum
    if (!equal(Tprime_check, proof.Tprime)) {
        return false;
    }
    const ATMarshal = marshalPoint(proof.A_T);
    const ATprimeMarshal = marshalPoint(proof.A_Tprime);
    buf = concat(buf, ATMarshal);
    buf = concat(buf, ATprimeMarshal);
    // compute the challenge
    const c = mimcHash(buf);
    for (var i = 0; i < proof.As.length; i++) {
        const Ai = proof.As[i];
        const binaryRes = verifyBinary(Ai, proof.Cas[i], proof.Cbs[i], proof.G, proof.H, proof.Fs[i], proof.Zas[i], proof.Zbs[i], c);
        if (!binaryRes) {
            return false;
        }
    }
    const sameComRes = verifyCommitmentSameValue(proof.A_T, proof.A_Tprime, proof.T, proof.Tprime, proof.G, proof.H, proof.Zb, proof.Zr, proof.Zrprime, c);
    if (!sameComRes) {
        return false;
    }
    return true;
}


/*
    commitBinary makes a random commitment to binary proof
    @b: binary value
    @g,h: generators
*/
export const commitBinary = (b: BigInt, g: Point, h: Point): { Ca: Point, Cb: Point, a: BigInt, s: BigInt, t: BigInt } => {
    if (b !== BigInt(0) && b !== BigInt(1)) {
        throw new Error('err: not binary number');
    }
    // a,s,t \gets_r \mathbb{Z}_p
    const a = randomValue();
    const s = randomValue();
    const t = randomValue();
    const ab = ffMul(a, b);
    const Ca = commit(a, s, g, h);
    const Cb = commit(ab, t, g, h);
    return {Ca: Ca, Cb: Cb, a: a, s: s, t: t};
}

/*
    respondBinary makes a response to binary proof
    @b: binary value
    @r: random value
    @a,s,t: random values for random commitments
    @c: the challenge
*/
export const respondBinary = (b: BigInt, r: BigInt, a: BigInt, s: BigInt, t: BigInt, c: BigInt): { f: BigInt, za: BigInt, zb: BigInt } => {
    if (b !== BigInt(0) && b !== BigInt(1)) {
        throw new Error('err: not binary number');
    }
    // f = bc + a
    const f = ffAddMod(ffMul(c, b), a, Order);
    // za = rc + s
    const za = ffAddMod(ffMul(r, c), s, Order);
    // zb = r(c - f) + t
    var zb = ffSub(c, f);
    zb = ffMul(r, zb);
    zb = ffAddMod(zb, t, Order);
    return {f: f, za: za, zb: zb};
}

/*
    verifyBinary verify a binary proof
    @A: pedersen commitment for the binary value
    @Ca,Cb: binary proof commitment
    @g,h: generators
    @f,za,zb: binary proof response
    @c: the challenge
*/
export const verifyBinary = (A: Point, Ca: Point, Cb: Point, g: Point, h: Point, f: BigInt, za: BigInt, zb: BigInt, c: BigInt): boolean => {
    // A^c Ca == Com(f,za)
    const r1 = commit(f, za, g, h);
    const l1 = addPoint(scalarMul(A, c), Ca);
    const l1r1 = equal(l1, r1);
    if (!l1r1) {
        return false;
    }
    // A^{c-f} Cb == Com(0,zb)
    const r2 = scalarMul(h, zb);
    const l2 = addPoint(scalarMul(A, ffSub(c, f)), Cb);
    const l2r2 = equal(l2, r2);
    return l2r2;
}

/*
    commitCommitmentSameValue makes a random commitment to the same value pedersen commitment proof
    @g,h: generators
*/
const commitCommitmentSameValue = (g: Point, h: Point): { A_T: Point, A_Tprime: Point, alpha_b: BigInt, alpha_r: BigInt, alpha_rprime: BigInt } => {
    // a,s,t \gets_R \mathbb{Z}_p
    const alpha_b = randomValue();
    const alpha_r = randomValue();
    const alpha_rprime = randomValue();
    const g_alphab = scalarMul(g, alpha_b);
    const A_T = addPoint(g_alphab, scalarMul(h, alpha_r));
    const A_Tprime = addPoint(g_alphab, scalarMul(h, alpha_rprime));
    return {A_T: A_T, A_Tprime: A_Tprime, alpha_b: alpha_b, alpha_r: alpha_r, alpha_rprime: alpha_rprime};
}

/*
    respondCommitmentSameValue makes a response to the same value pedersen commitment proof
    @b: the value
    @r: the random value for b
    @rprime: another random value for b
    @alpha_b,alpha_r,alpha_rprime: random values generated in commit phase
    @c: the challenge
*/
const respondCommitmentSameValue = (b: BigInt, r: BigInt, rprime: BigInt, alpha_b: BigInt, alpha_r: BigInt, alpha_rprime: BigInt, c: BigInt): { zb: BigInt, zr: BigInt, zrprime: BigInt } => {
    // zb = alpha_b + cb
    const zb = ffAddMod(alpha_b, ffMul(c, b), Order);
    // zr = alpha_r + cr
    const zr = ffAddMod(alpha_r, ffMul(c, r), Order);
    // zrprime = alpha_rprime + c rprime
    const zrprime = ffAddMod(alpha_rprime, ffMul(c, rprime), Order);
    return {zb: zb, zr: zr, zrprime: zrprime};
}

/*
    verifyCommitmentSameValue verify the same value pedersen commitment proof
    @A_T,A_Tprime: commitment values generated in commit phase
    @T,Tprime: two pedersen commitments for the same b
    @g,h: generators
    @zb,zr,zrprime: commitmentSameValue response
    @c: the challenge
*/
const verifyCommitmentSameValue = (A_T: Point, A_Tprime: Point, T: Point, Tprime: Point, g: Point, h: Point, zb: BigInt, zr: BigInt, zrprime: BigInt, c: BigInt): boolean => {
    // g^{zb} h^{zr} == A_T T^c
    const gzb = scalarMul(g, zb);
    const l1 = addPoint(gzb, scalarMul(h, zr));
    const r1 = addPoint(A_T, scalarMul(T, c));
    if (!equal(l1, r1)) {
        return false;
    }
    // g^{zb} h^{zrprime} == A_T' T'^c
    const hzrprime = scalarMul(h, zrprime);
    const l2 = addPoint(gzb, hzrprime);
    const r2 = addPoint(A_Tprime, scalarMul(Tprime, c));
    return equal(l2, r2);
}

