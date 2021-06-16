import { Point, scalarMul, addPoint } from '../ecc';

export const commit = (a: BigInt, r: BigInt, g: Point, h: Point): Point => {
    const ga = scalarMul(g, a);
    const hr = scalarMul(h, r);
    return addPoint(ga, hr);
}