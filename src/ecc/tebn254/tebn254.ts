import * as bigintCryptoUtils from 'bigint-crypto-utils';

var ffjavascript = require('ffjavascript');

const F1Field = ffjavascript.F1Field;
const Scalar = ffjavascript.Scalar;
const utils = ffjavascript.utils;


const p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const F = new F1Field(p);

export const Generator = {
    X: F.e("9671717474070082183213120605117400219616337014328744928644933853176787189663"),
    Y: F.e("16950150798460657717958625567821834550301663161624707787222815936182638968203")
};

const subOrder = Scalar.fromString("2736030358979909402780800718157159386076813972158567259200215660948447373041");
const A = F.neg(F.one);
const D = F.e("12181644023421730124874158521699555681764249180949974110617291017600649128846");

export interface Point {
    X: BigInt,
    Y: BigInt,
}

export const zeroPoint = (): Point => {
    return { X: F.e('0'), Y: F.e('1') };
}

export const newPoint = (x: string, y: string): Point => {
    return { X: F.e(x), Y: F.e(y) };
}

export const addPoint = (a: Point, b: Point): Point => {

    const res: Point = zeroPoint();

    /* does the equivalent of:
     res[0] = bigInt((a.X*b.Y + b.X*a.Y) *  bigInt(bigInt("1") + d*a.X*b.X*a.Y*b.Y).inverse(q)).affine(q);
    res[1] = bigInt((a.Y*b.Y - cta*a.X*b.X) * bigInt(bigInt("1") - d*a.X*b.X*a.Y*b.Y).inverse(q)).affine(q);
    */

    const xv = F.mul(a.X, b.Y);
    const yu = F.mul(a.Y, b.X);
    res.X = F.add(xv, yu);

    const xu = F.mul(a.X, b.X);
    const yv = F.mul(a.Y, b.Y);
    res.Y = F.add(xu, yv);

    const dxyuv = F.mul(
        F.mul(xv, yu),
        D,
    )

    const denx = F.add(F.one, dxyuv);
    const deny = F.sub(F.one, dxyuv);
    res.X = F.div(res.X, denx);
    res.Y = F.div(res.Y, deny);
    return res;
}

export const scalarBaseMul = (e: BigInt): Point => {
    return scalarMul(Generator, e);
}

export const scalarMul = (base: Point, e: BigInt): Point => {
    let res = zeroPoint();

    if (e < BigInt(0)) {
        e = Scalar.neg(e);
        base = negPoint(base);
    }

    let rem = e;
    let exp = base;


    while (!Scalar.isZero(rem)) {
        if (Scalar.isOdd(rem)) {
            res = addPoint(res, exp);
        }
        exp = addPoint(exp, exp);
        rem = Scalar.shiftRight(rem, 1);
    }

    return res;
}

export const isInSubgroup = (P: Point): boolean => {
    if (!isInCurve(P)) return false;
    const res = scalarMul(P, subOrder);
    return (F.isZero(res.X) && F.eq(res.Y, F.one));
}

export const isInCurve = (P: Point): boolean => {

    const x2 = F.square(P.X);
    const y2 = F.square(P.Y);

    if (!F.eq(
        F.add(F.mul(A, x2), y2),
        F.add(F.one, F.mul(F.mul(x2, y2), D)))) return false;

    return true;
}

export const marshalPoint = (P: Point): Buffer => {
    const buff = utils.leInt2Buff(P.Y, 32);
    if (F.lt(P.X, F.zero)) {
        buff[31] = buff[31] | 0x80;
    }
    return buff;
}

export const unmarshalPoint = (_buff: Buffer): Point => {
    const buff = Buffer.from(_buff);
    let sign = false;
    const P = zeroPoint();
    if (buff[31] & 0x80) {
        sign = true;
        buff[31] = buff[31] & 0x7F;
    }
    P.Y = utils.leBuff2int(buff);
    if (Scalar.gt(P.Y, p)) return P;

    const y2 = F.square(P.Y);

    let x = F.sqrt(F.div(
        F.sub(F.one, y2),
        F.sub(A, F.mul(D, y2))));

    if (x == null) return P;

    if (sign) x = F.neg(x);

    P.X = x;

    return P;
}

export const negPoint = (p: Point): Point => {
    return { X: F.neg(p.X), Y: p.Y };
}

export const equal = (a: Point, b: Point): boolean => {
    return F.eq(a.X, b.X) && F.eq(a.Y, b.Y);
}

export const randomValue = (): BigInt => {
    const r = bigintCryptoUtils.randBetween(subOrder);
    return r;
}