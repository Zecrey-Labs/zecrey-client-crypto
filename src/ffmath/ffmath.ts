import {Scalar} from '../ecc';
import * as bigintCryptoUtils from 'bigint-crypto-utils';

export const ffAdd = (a: BigInt, b: BigInt): BigInt => {
    const ab = Scalar.add(a, b);
    return ab;
}

export const ffAddMod = (a: BigInt, b: BigInt, Order: BigInt): BigInt => {
    const ab = Scalar.add(a, b);
    const abMod = ffMod(ab, Order);
    return abMod;
}

export const ffSub = (a: BigInt, b: BigInt): BigInt => {
    const ab = Scalar.sub(a, b);
    return ab;
}

export const ffSubMod = (a: BigInt, b: BigInt, Order: BigInt): BigInt => {
    const ab = Scalar.sub(a, b);
    const abMod = ffMod(ab, Order);
    return abMod;
}

export const ffMul = (a: BigInt, b: BigInt): BigInt => {
    const ab = Scalar.mul(a, b);
    return ab;
}

export const ffMulMod = (a: BigInt, b: BigInt, Order: BigInt): BigInt => {
    const ab = Scalar.mul(a, b);
    const abMod = ffMod(ab, Order);
    return abMod;
}


export const ffModInverse = (a: BigInt, Order: BigInt): BigInt => {
    const r = bigintCryptoUtils.modInv(a.valueOf(), Order.valueOf());
    return r;
}

export const ffDiv = (a: BigInt, b: BigInt): BigInt => {
    const ab = Scalar.div(a, b);
    return ab;
}

export const ffMod = (a: BigInt, Order: BigInt): BigInt => {
    const aMod = Scalar.mod(a, Order);
    const res = Scalar.mod(Scalar.add(aMod, Order), Order);
    return res;
}
