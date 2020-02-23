import { Resolver } from "did-resolver";
import { SignPdfError } from "node-signpdf";
import { JWT } from "jose";
import { DIDJwt } from "did-jwt";

import { InvalidSignatureError } from "./errors";

import Crypto from "crypto";

export class PdfJwtVerifier {
  private resolver: Resolver;

  constructor(resolver: Resolver) {
    this.resolver = resolver;
  }

  public async verifySignedPdf(pdfBuffer: Buffer): Promise<object> {
    return new Promise<object>(async (onSuccess: Function, onError: Function) => {
      try {
        const signatures: object = PdfJwtVerifier.extractSignatures(pdfBuffer);

        for (const index of Object.keys(signatures)) {

          const signature: object = signatures[index];
          const jwt: string = signature["jwt"];
          const decodedJwt: object = JWT.decode(jwt);

          // Validate the signature
          if (!("iss" in decodedJwt))
            throw new InvalidSignatureError("Issuer not found in the signature!");

          if (!("checksum" in decodedJwt))
            throw new InvalidSignatureError("Checksum not found in the signature!");

          let digestAlgorithm: string = "sha256";

          if ("digest_algorithm" in decodedJwt)
            digestAlgorithm = decodedJwt["digest_algorithm"];

          // Calculate the checksum
          const checksum: string = Crypto.createHash(digestAlgorithm || "sha256")
            .update(signature["signedData"])
            .digest("hex").toString();

          // Verify the calculated checksum against the signed one
          if (checksum != decodedJwt["checksum"])
            throw new InvalidSignatureError("Signed checkum is incorrect!");

          const issuerDid: string = decodedJwt["iss"];

          await DIDJwt.verify(this.resolver, jwt, issuerDid);
        };
        onSuccess(signatures);
      } catch (err) {
        onError(err);
      }

    });


  }

  public static extractSignatures(pdfBuffer: Buffer): object {

    if (!(pdfBuffer instanceof Buffer)) {
      throw new SignPdfError(
        "PDF expected as Buffer.",
        SignPdfError.TYPE_INPUT,
      );
    }

    const pdfString: string = pdfBuffer.toString();

    const signatureCount: number = (pdfString.match(/\/ByteRange \[/g) || []).length;

    let signatures: object = {};

    for (let index: number = 0; index < signatureCount; index++) {
      const byteRangePos: number = PdfJwtVerifier
        .getSubstringIndex(pdfString.toString(), "/ByteRange", index + 1);
      if (byteRangePos == -1) {
        throw new SignPdfError(
          "Failed to locate ByteRange.",
          SignPdfError.TYPE_PARSE,
        );
      }

      const byteRangeEnd: number = pdfString.indexOf("]", byteRangePos);
      if (byteRangeEnd == -1) {
        throw new SignPdfError(
          "Failed to locate the end of the ByteRange.",
          SignPdfError.TYPE_PARSE,
        );
      }

      const byteRange: string = pdfString.slice(byteRangePos, byteRangeEnd + 1).toString();
      const matches: any = (/\/ByteRange \[(\d+) +(\d+) +(\d+) +(\d+) *\]/).exec(byteRange);
      if (matches == null) {
        throw new SignPdfError(
          "Failed to parse the ByteRange.",
          SignPdfError.TYPE_PARSE,
        );
      }

      const ByteRange = matches.slice(1).map(Number);
      const signedData: Buffer = Buffer.concat([
        pdfBuffer.slice(ByteRange[0], ByteRange[0] + ByteRange[1]),
        pdfBuffer.slice(ByteRange[2], ByteRange[2] + ByteRange[3]),
      ]);

      const jwt: string =
        pdfBuffer.slice(ByteRange[0] + ByteRange[1] + 1, ByteRange[2])
          .toString().replace(/(?:00|>)+$/, "").slice(0, -1);

      signatures[index] = { jwt, signedData };
    }

    return signatures;
  }

  public static getSubstringIndex(pdf: string, substring: string,
    n: number): number {
    let times: number = 0, index = null;

    while (times < n && index !== -1) {
      index = pdf.indexOf(substring, index + 1);
      times++;
    }

    return index;
  }
}
