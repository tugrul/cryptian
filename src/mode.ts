
import { AlgorithmBlock } from "./algorithm/block";

export declare class Mode {
    constructor(algorithm: AlgorithmBlock, iv: string|Buffer);
    transform(data: string|Buffer): Buffer;
    isPaddingRequired(): boolean;
    getBlockSize(): number;
}
