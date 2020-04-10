import { DIDJwt } from "did-jwt";
import { JWK } from "node-jose";
import JWT from "jsonwebtoken"
import { SignPdfError } from "node-signpdf";

import {
  plainAddPlaceholder
} from "node-signpdf/dist/helpers";

import Crypto from "crypto";

export const DEFAULT_BYTE_RANGE_PLACEHOLDER: string = "**********";
const DEFAULT_SIGNATURE_LENGTH: number = 8192;

export class PdfJwtSigner {

  private byteRangePlaceholder: string;

  constructor();
  constructor(byteRangePlaceholder?: string) {
    this.byteRangePlaceholder = byteRangePlaceholder ||
      DEFAULT_BYTE_RANGE_PLACEHOLDER;
  }

  public signPdf(pdfBuffer: Buffer, jwk: JWK.Key, payload: object);
  public signPdf(pdfBuffer: Buffer, jwk: JWK.Key, payload: object,
    signOptions: JWT.SignOptions);
  public signPdf(pdfBuffer: Buffer, jwk: JWK.Key, payload: object,
    signOptions: JWT.SignOptions, signatureLength?: Number);
  public signPdf(pdfBuffer: Buffer, jwk: JWK.Key, payload: object,
    signOptions?: JWT.SignOptions, signatureLength?: Number, digestAlgorithm?: string): Buffer {
    if (!(pdfBuffer instanceof Buffer)) {
      throw new SignPdfError(
        "PDF expected as Buffer.",
        SignPdfError.TYPE_INPUT,
      );
    }
    // Add the place holder
    let pdf: Buffer = plainAddPlaceholder({
      pdfBuffer: pdfBuffer,
      signatureLength: signatureLength || DEFAULT_SIGNATURE_LENGTH
    });

    // Find the ByteRange placeholder.
    const byteRangePlaceholder: Array<any> = [
      0,
      `/${this.byteRangePlaceholder}`,
      `/${this.byteRangePlaceholder}`,
      `/${this.byteRangePlaceholder}`,
    ];

    const byteRangeString: string = `/ByteRange [${byteRangePlaceholder.join(" ")}]`;
    const byteRangePos: number = pdf.indexOf(byteRangeString);
    if (byteRangePos === -1) {
      throw new SignPdfError(
        `Could not find ByteRange placeholder: ${byteRangeString}`,
        SignPdfError.TYPE_PARSE,
      );
    }

    // Calculate the actual ByteRange that needs to replace the placeholder.
    const byteRangeEnd: number = byteRangePos + byteRangeString.length;
    const contentsTagPos: number = pdf.indexOf("/Contents ", byteRangeEnd);
    const placeholderPos: number = pdf.indexOf("<", contentsTagPos);
    const placeholderEnd: number = pdf.indexOf(">", placeholderPos);
    const placeholderLengthWithBrackets: number = (placeholderEnd + 1) - placeholderPos;
    const placeholderLength: number = placeholderLengthWithBrackets - 2;
    const byteRange: Array<number> = [0, 0, 0, 0];
    byteRange[1] = placeholderPos;
    byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
    byteRange[3] = pdf.length - byteRange[2];
    let actualByteRange: string = `/ByteRange [${byteRange.join(" ")}]`;
    actualByteRange += " ".repeat(byteRangeString.length - actualByteRange.length);

    // Replace the /ByteRange placeholder with the actual ByteRange
    pdf = Buffer.concat([
      pdf.slice(0, byteRangePos),
      Buffer.from(actualByteRange),
      pdf.slice(byteRangeEnd),
    ]);

    // Remove the placeholder signature
    pdf = Buffer.concat([
      pdf.slice(0, byteRange[1]),
      pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
    ]);

    // Now create the jwt
    const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
      .update(pdf)
      .digest("hex").toString();

    const sigPayload: object = {
      "checksum": checksum,
      "digest_algorithm": digestAlgorithm || "sha256"
    };

    Object.keys(payload).forEach((key) => {
      sigPayload[key] = payload[key];
    });

    const jwt: string = DIDJwt.sign(sigPayload, jwk, signOptions);

    // Encode the jwt to hex
    let jwtHex: string = Buffer.from(jwt, "utf8").toString("hex");

    if (jwtHex.length > placeholderLength) {
      throw new SignPdfError(
        `Signature exceeds placeholder length: ${pdf.length * 2} > ${placeholderLength}`,
        SignPdfError.TYPE_INPUT,
      );
    }

    // Pad the jwt hex
    const padding: string = '0'.repeat(placeholderLength - jwtHex.length);
    jwtHex += padding;
    // Add the signature to the file
    pdf = Buffer.concat([
      pdf.slice(0, byteRange[1]),
      Buffer.from(`<${jwtHex}>`),
      pdf.slice(byteRange[1]),
    ]);

    return pdf;
  }
}
