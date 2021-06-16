import * as secp from "noble-secp256k1";

export const getPublicKey = async (sk: string) => {
    const pk = secp.getPublicKey(sk);
    return pk;
}