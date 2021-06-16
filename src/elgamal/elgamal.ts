import { Point, randomValue, scalarMul, scalarBaseMul, G, H, Scalar, addPoint, negPoint, equal, Order } from '../ecc';
import { commit } from '../commitment';
import { ffModInverse } from '../ffmath';

export interface ElGamalEnc {
    CL: Point,
    CR: Point,
}

/**
Generate key pair, sk \gets_R mathbb{Z}_p, pk = g^{sk}
*/
export const genKeyPair = (): { sk: BigInt, pk: Point } => {
    const sk = randomValue();
    const pk = scalarBaseMul(sk);
    return { sk: sk, pk: pk };
}

/**
Encryption method: C_L = pk^r, C_R = g^r h^b
@b: the amount needs to be encrypted
@r: the random value
@pk: public key
*/
export const elgamalEnc = (b: BigInt, r: BigInt, pk: Point): ElGamalEnc | null => {
    // pk^r
    const CL = scalarMul(pk, r);
    // g^r h^b
    const CR = commit(r, b, G, H)
    return { CL: CL, CR: CR };
}

/**
Decrypt Method: h^b = C_R / (C_L)^{sk^{-1}}, then compute b by brute-force
@enc: encryption entity
@sk: the private key of the encryption public key
@Max: the max size of b
*/
export const elgamalDec = (enc: ElGamalEnc, sk: BigInt, Max: number): BigInt | null => {
    // (pk^r)^{sk^{-1}}
    const skInv = ffModInverse(sk, Order);
    const gExpr = scalarMul(enc.CL, skInv);
    const hExpb = addPoint(enc.CR, negPoint(gExpr));
    for (var i = 0; i < Max; i++) {
        const b = BigInt(i);
        const hi = scalarMul(H, b);
        if (equal(hi, hExpb)) {
            return b;
        }
    }
    return null;
}

/**
Decrypt Method: h^b = C_R / (C_L)^{sk^{-1}}, then compute b by brute-force(from start)
@enc: encryption entity
@sk: the private key of the encryption public key
@Max: the max size of b
*/
export const elgamalDecByStart = (enc: ElGamalEnc, sk: BigInt, start: number, Max: number): BigInt | null => {
    // (pk^r)^{sk^{-1}}
    const skInv = Scalar.modInverse(sk, G);
    const gExpr = scalarMul(enc.CL, skInv);
    const hExpb = addPoint(enc.CR, negPoint(gExpr));
    for (var i = start; i < Max; i++) {
        const b = BigInt(i);
        const hi = scalarMul(H, b);
        if (equal(hi, hExpb)) {
            return b;
        }
    }
    return null;
}