/// <reference types="node" />
import { JWK } from "node-jose";
import JWT from "jsonwebtoken";
export declare const DEFAULT_BYTE_RANGE_PLACEHOLDER: string;
export declare class PdfJwtSigner {
    private byteRangePlaceholder;
    constructor();
    signPdf(pdfBuffer: Buffer, jwk: JWK.ECKey, payload: object): any;
    signPdf(pdfBuffer: Buffer, jwk: JWK.ECKey, payload: object, signOptions: JWT.SignOptions): any;
}
