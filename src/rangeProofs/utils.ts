import { ffDiv, ffMod, ffMulMod } from '../ffmath';
import { Order } from '../ecc';

/*
    toBinary receives as input a bigint x and outputs an array of integers such that
    x = sum(xi.2^i), i.e. it returns the decomposition of x into base 2.
*/
export const toBinary = (x: BigInt, l: number): BigInt[] => {
    const resultBigInt = new Array<BigInt>(l);
    const uInt: BigInt = BigInt(2);
    for (var i = 0; i < l; i++) {
        resultBigInt[i] = ffMod(x, uInt);
        x = ffDiv(x, uInt);
    }
    return resultBigInt;
}

/*
powerOf returns a vector composed by powers of x.
*/
export const powerOfVec = (y: BigInt, n: number): BigInt[] => {

    const result = new Array<BigInt>(n);
    var current: BigInt = BigInt(1);
    for (var i = 0; i < n; i++) {
        result[i] = current;
        current = ffMulMod(y, current, Order);
    }
    return result;
}
