/// <reference types="node" />
import { Resolver } from "did-resolver";
export declare class PdfJwtVerifier {
    private resolver;
    constructor(resolver: Resolver);
    verifySignedPdf(pdfBuffer: Buffer): Promise<object>;
    static extractSignatures(pdfBuffer: Buffer): object;
    static getSubstringIndex(pdf: string, substring: string, n: number): number;
}
