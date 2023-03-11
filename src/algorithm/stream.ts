
export interface AlgorithmStream {
    constructor(): this;
    setKey(key:string|Buffer): this;
    setIv(key:string|Buffer): this;
    encrypt(plaintext: string|Buffer): Buffer;
    decrypt(ciphertext: string|Buffer): Buffer;
    getName(): string;
    getVersion(): number;
    getKeySizes(): Array<number>;
    reset(): this;
    getIvSize(): number;
}
