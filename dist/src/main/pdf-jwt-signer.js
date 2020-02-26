"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var did_jwt_1 = require("did-jwt");
var node_signpdf_1 = require("node-signpdf");
/*import {
  plainAddPlaceholder
} from "../../node_modules/node-signpdf/dist/helpers";*/
var helpers_1 = require("node-signpdf/dist/helpers");
var crypto_1 = __importDefault(require("crypto"));
exports.DEFAULT_BYTE_RANGE_PLACEHOLDER = "**********";
var PdfJwtSigner = /** @class */ (function () {
    function PdfJwtSigner(byteRangePlaceholder) {
        this.byteRangePlaceholder = byteRangePlaceholder ||
            exports.DEFAULT_BYTE_RANGE_PLACEHOLDER;
    }
    PdfJwtSigner.prototype.signPdf = function (pdfBuffer, jwk, payload, signOptions, digestAlgorithm) {
        if (!(pdfBuffer instanceof Buffer)) {
            throw new node_signpdf_1.SignPdfError("PDF expected as Buffer.", node_signpdf_1.SignPdfError.TYPE_INPUT);
        }
        // Add the place holder
        var pdf = helpers_1.plainAddPlaceholder({ pdfBuffer: pdfBuffer });
        // Find the ByteRange placeholder.
        var byteRangePlaceholder = [
            0,
            "/" + this.byteRangePlaceholder,
            "/" + this.byteRangePlaceholder,
            "/" + this.byteRangePlaceholder,
        ];
        var byteRangeString = "/ByteRange [" + byteRangePlaceholder.join(" ") + "]";
        var byteRangePos = pdf.indexOf(byteRangeString);
        if (byteRangePos === -1) {
            throw new node_signpdf_1.SignPdfError("Could not find ByteRange placeholder: " + byteRangeString, node_signpdf_1.SignPdfError.TYPE_PARSE);
        }
        // Calculate the actual ByteRange that needs to replace the placeholder.
        var byteRangeEnd = byteRangePos + byteRangeString.length;
        var contentsTagPos = pdf.indexOf("/Contents ", byteRangeEnd);
        var placeholderPos = pdf.indexOf("<", contentsTagPos);
        var placeholderEnd = pdf.indexOf(">", placeholderPos);
        var placeholderLengthWithBrackets = (placeholderEnd + 1) - placeholderPos;
        var placeholderLength = placeholderLengthWithBrackets - 2;
        var byteRange = [0, 0, 0, 0];
        byteRange[1] = placeholderPos;
        byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
        byteRange[3] = pdf.length - byteRange[2];
        var actualByteRange = "/ByteRange [" + byteRange.join(" ") + "]";
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
        var checksum = crypto_1.default.createHash(digestAlgorithm || "sha256")
            .update(pdf)
            .digest("hex").toString();
        var sigPayload = {
            "checksum": checksum,
            "digest_algorithm": digestAlgorithm || "sha256"
        };
        Object.keys(payload).forEach(function (key) {
            sigPayload[key] = payload[key];
        });
        var jwt = did_jwt_1.DIDJwt.sign(sigPayload, jwk, signOptions);
        if ((jwt.length * 2) > placeholderLength) {
            throw new node_signpdf_1.SignPdfError("Signature exceeds placeholder length: " + pdf.length * 2 + " > " + placeholderLength, node_signpdf_1.SignPdfError.TYPE_INPUT);
        }
        // Pad the jwt
        var padding = '*'.repeat(placeholderLength - jwt.length);
        jwt += padding;
        // Add the signature to the file
        pdf = Buffer.concat([
            pdf.slice(0, byteRange[1]),
            Buffer.from("<" + jwt + ">"),
            pdf.slice(byteRange[1]),
        ]);
        return pdf;
    };
    return PdfJwtSigner;
}());
exports.PdfJwtSigner = PdfJwtSigner;
