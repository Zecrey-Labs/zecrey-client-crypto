import {addPoint, equal, G, H, negPoint, Order, Point, randomValue, scalarMul} from '../ecc';
import {ComRangeProof} from '../rangeProofs';
import {elgamalEnc, ElGamalEnc} from '../elgamal';
import {ffAdd} from '../ffmath';
import {commit} from '../commitment';


export interface PTransferProof {
    SubProofs: PTransferSubProof[],
    A_sum: Point,
    A_Pts: Point[],
    Z_tsks: BigInt[],
    Pts: Point[],
    C1: BigInt,
    C2: BigInt,
    G: Point,
    H: Point,
    Ht: Point,
}

export interface PTransferSubProof {
    // sigma protocol commitment values
    A_CLDelta: Point,
    A_CRDelta: Point,
    A_YDivCRDelta: Point,
    A_YDivT: Point,
    A_T: Point,
    A_pk: Point,
    A_TDivCPrime: Point,
    // respond values
    Z_r: BigInt,
    Z_bDelta: BigInt,
    Z_rstarSubr: BigInt,
    Z_rstarSubrbar: BigInt,
    Z_rbar: BigInt,
    Z_bprime: BigInt,
    Z_sk: BigInt,
    Z_skInv: BigInt,
    // range proof
    CRangeProof: ComRangeProof,
    // common inputs
    // original balance enc
    C: ElGamalEnc,
    // delta balance enc
    CDelta: ElGamalEnc,
    // new pedersen commitment for new balance
    T: Point,
    // new pedersen commitment for deleta balance or new balance
    Y: Point,
    // public key
    Pk: Point,
    // T (C_R + C_R^{\Delta})^{-1}
    TCRprimeInv: Point,
    // (C_L + C_L^{\Delta})^{-1}
    CLprimeInv: Point,
}

export interface PTransferProofRelation {
    Statements?: PTransferProofStatement[]
    G: Point
    H: Point
    Ht?: Point
    Pts?: Point[]
    Order: BigInt
    TokenId: number
}

export interface PTransferProofStatement {
    // ------------- public ---------------------
    // original balance enc
    C: ElGamalEnc
    // delta balance enc
    CDelta: ElGamalEnc
    // new pedersen commitment for new balance
    T: Point
    // new pedersen commitment for deleta balance or new balance
    Y: Point
    // public key
    Pk: Point
    // T (C_R + C_R^{\Delta})^{-1}
    TCRprimeInv: Point
    // (C_L + C_L^{\Delta})^{-1}
    CLprimeInv: Point
    // ----------- private ---------------------
    // delta balance
    BDelta: BigInt
    // copy for delta balance or new balance
    BStar: BigInt
    // new balance
    BPrime: BigInt
    // private key
    Sk: BigInt
    // random value for CDelta
    R: BigInt
    // random value for T
    RBar: BigInt
    // random value for Y
    RStar: BigInt
    // token id
    // TokenId: number
}

export interface TransferCommitValues {
    // random values
    alpha_r: BigInt,
    alpha_bDelta: BigInt,
    alpha_rstarSubr: BigInt,
    alpha_rstarSubrbar: BigInt,
    alpha_rbar: BigInt,
    alpha_bprime: BigInt,
    alpha_sk: BigInt,
    alpha_skInv: BigInt
    // commit
    A_CLDelta: Point,
    A_CRDelta: Point,
    A_YDivCRDelta: Point,
    A_YDivT: Point,
    A_T: Point,
    A_pk: Point,
    A_TDivCPrime: Point
}
