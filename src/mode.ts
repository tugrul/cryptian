
import { AlgorithmBlock } from "./algorithm/block";

export interface Mode {
    constructor(algorithm: AlgorithmBlock, iv: string|Buffer): this;
    transform(data: string|Buffer): Buffer;
    isPaddingRequired(): boolean;
    getBlockSize(): number;
}
