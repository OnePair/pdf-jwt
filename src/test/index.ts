import { PdfJwtSigner, PdfJwtVerifier } from "../main";
import { JWK } from "jose";
import { DidJwk, getResolver } from "node-did-jwk";
import { Resolver } from "did-resolver";

import path from "path";
import fs from "fs";

describe("PDF Jsig tests", () => {
  let jwk1: JWK.ECKey;
  let jwk2: JWK.ECKey;

  let did1: DidJwk;
  let did2: DidJwk;

  let resolver: Resolver;

  let pdf1: Buffer;
  let pdf1Signed: Buffer;
  let pdf1SignedTwice: Buffer;

  let pdfSigner: PdfJwtSigner;
  let pdfVerifier: PdfJwtVerifier;

  before(() => {
    const jwkResolver = getResolver();
    resolver = new Resolver({
      jwk: jwkResolver
    });

    jwk1 = JWK.generateSync("EC", "P-256");
    jwk2 = JWK.generateSync("EC", "P-256");

    did1 = new DidJwk(jwk1);
    did2 = new DidJwk(jwk2);

    pdf1 = fs.readFileSync(path.join(__dirname, "pdf1.pdf"));

    pdfSigner = new PdfJwtSigner();
    pdfVerifier = new PdfJwtVerifier(resolver);
  });


  describe("Signing tests", () => {
    it("Should not throw an error when signing", async () => {
      pdf1Signed = await pdfSigner.signPdf(pdf1, jwk1,
        { firstName: "First Name" }, { issuer: did1.getDidUri() });

      fs.writeFileSync(path.join(__dirname, "pdf1-signed.pdf"), pdf1Signed);
    });

    it("Should not throw an error when adding another signature", async () => {
      pdf1SignedTwice = await pdfSigner.signPdf(pdf1Signed, jwk2,
        { firstName: "First Name" }, { issuer: did2.getDidUri() });

      fs.writeFileSync(path.join(__dirname, "pdf1-signed-twice.pdf"), pdf1SignedTwice);
    });
  });

  describe("Verification tests", () => {
    it("Signed PDF verification should pass", async () => {
      await pdfVerifier.verifySignedPdf(pdf1Signed);
    });

    it("Verification of PDF signed twice should pass", async () => {
      await pdfVerifier.verifySignedPdf(pdf1SignedTwice)
    });
  });
});
