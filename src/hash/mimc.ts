import { F } from "../ecc";
import { SHA3 } from 'sha3';
import * as bigintConversion from 'bigint-conversion'

const hash = new SHA3(256);

const SEED = "ZecreyMIMCSeed";
// 
const mimcNbRounds = 91;
// BlockSize size that mimc consumes
const BlockSize = 32;

function BufferToBigInt(buf: Buffer): bigint {
    return bigintConversion.bufToBigint(buf);
}

function BigIntToBuffer(bn: BigInt): Buffer {
    return (bigintConversion.bigintToBuf(bn.valueOf(), false)) as Buffer;
}

const newParams = (): BigInt[] => {
    var res: BigInt[] = [];
    var rnd = hash.update(Buffer.from(SEED)).digest();
    var value = BufferToBigInt(rnd);
    for (var i = 0; i < mimcNbRounds; i++) {
        hash.reset();
        const v = BigIntToBuffer(value);
        rnd = hash.update(v).digest();
        value = BufferToBigInt(rnd);
        res.push(F.e(value));
    }
    return res;
}

// Params constants for the mimc hash function
const params = newParams();

export const mimcHash = (data: Buffer): BigInt => {
    // if data size is not multiple of BlockSizes we padd:
    // .. || 0xaf8 -> .. || 0x0000...0af8
    var padData = Buffer.alloc(BlockSize);

    if (data.length % BlockSize != 0) {
        const q = Math.floor(data.length / BlockSize);
        const r = data.length % BlockSize;
        const buf1 = Buffer.alloc(q * BlockSize);
        const sliceq = data.slice(0, q * BlockSize);
        sliceq.copy(buf1, buf1.length - sliceq.length);
        const slicer = data.slice(q * BlockSize);
        const sliceRemainer = Buffer.alloc(BlockSize - r);
        padData = Buffer.concat([sliceq, sliceRemainer, slicer]);
    }

    const nbChunks = padData.length / BlockSize;
    var h;
    for (var i = 0; i < nbChunks; i++) {
        const x = F.e(BufferToBigInt(padData.slice(i * BlockSize, (i + 1) * BlockSize)).toString());
        h = encrypt(x);
        h = F.add(x, h);
    }
    return h;
}

const encrypt = (m: BigInt): BigInt => {
    const zero = F.e(0);
    for (var i = 0; i < mimcNbRounds; i++) {
        const tmp = F.add(F.add(m, zero), params[i]);
        m = F.square(tmp);
        m = F.square(m)
        m = F.mul(m, tmp);
    }
    m = F.add(m, zero);
    return m;
}

