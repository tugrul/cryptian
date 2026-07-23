
export class NotImplementedError extends Error {

    constructor(message?: string) {
        super(message);

        // Without this the name stays 'Error', which defeats the purpose of
        // having a distinct class when the error is logged or serialized.
        this.name = 'NotImplementedError';

        // Extending a builtin breaks the prototype chain when the output is
        // downlevelled, so instanceof would otherwise fail.
        Object.setPrototypeOf(this, NotImplementedError.prototype);
    }
}
