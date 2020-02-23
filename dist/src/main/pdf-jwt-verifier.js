"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var node_signpdf_1 = require("node-signpdf");
var jose_1 = require("jose");
var did_jwt_1 = require("did-jwt");
var errors_1 = require("./errors");
var crypto_1 = __importDefault(require("crypto"));
var PdfJwtVerifier = /** @class */ (function () {
    function PdfJwtVerifier(resolver) {
        this.resolver = resolver;
    }
    PdfJwtVerifier.prototype.verifySignedPdf = function (pdfBuffer) {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (onSuccess, onError) { return __awaiter(_this, void 0, void 0, function () {
                        var signatures, _i, _a, index, signature, jwt, decodedJwt, digestAlgorithm, checksum, issuerDid, err_1;
                        return __generator(this, function (_b) {
                            switch (_b.label) {
                                case 0:
                                    _b.trys.push([0, 5, , 6]);
                                    signatures = PdfJwtVerifier.extractSignatures(pdfBuffer);
                                    _i = 0, _a = Object.keys(signatures);
                                    _b.label = 1;
                                case 1:
                                    if (!(_i < _a.length)) return [3 /*break*/, 4];
                                    index = _a[_i];
                                    signature = signatures[index];
                                    jwt = signature["jwt"];
                                    decodedJwt = jose_1.JWT.decode(jwt);
                                    // Validate the signature
                                    if (!("iss" in decodedJwt))
                                        throw new errors_1.InvalidSignatureError("Issuer not found in the signature!");
                                    if (!("checksum" in decodedJwt))
                                        throw new errors_1.InvalidSignatureError("Checksum not found in the signature!");
                                    digestAlgorithm = "sha256";
                                    if ("digest_algorithm" in decodedJwt)
                                        digestAlgorithm = decodedJwt["digest_algorithm"];
                                    checksum = crypto_1.default.createHash(digestAlgorithm || "sha256")
                                        .update(signature["signedData"])
                                        .digest("hex").toString();
                                    // Verify the calculated checksum against the signed one
                                    if (checksum != decodedJwt["checksum"])
                                        throw new errors_1.InvalidSignatureError("Signed checkum is incorrect!");
                                    issuerDid = decodedJwt["iss"];
                                    return [4 /*yield*/, did_jwt_1.DIDJwt.verify(this.resolver, jwt, issuerDid)];
                                case 2:
                                    _b.sent();
                                    _b.label = 3;
                                case 3:
                                    _i++;
                                    return [3 /*break*/, 1];
                                case 4:
                                    ;
                                    onSuccess(signatures);
                                    return [3 /*break*/, 6];
                                case 5:
                                    err_1 = _b.sent();
                                    onError(err_1);
                                    return [3 /*break*/, 6];
                                case 6: return [2 /*return*/];
                            }
                        });
                    }); })];
            });
        });
    };
    PdfJwtVerifier.extractSignatures = function (pdfBuffer) {
        if (!(pdfBuffer instanceof Buffer)) {
            throw new node_signpdf_1.SignPdfError("PDF expected as Buffer.", node_signpdf_1.SignPdfError.TYPE_INPUT);
        }
        var pdfString = pdfBuffer.toString();
        var signatureCount = (pdfString.match(/\/ByteRange \[/g) || []).length;
        var signatures = {};
        for (var index = 0; index < signatureCount; index++) {
            var byteRangePos = PdfJwtVerifier
                .getSubstringIndex(pdfString.toString(), "/ByteRange", index + 1);
            if (byteRangePos == -1) {
                throw new node_signpdf_1.SignPdfError("Failed to locate ByteRange.", node_signpdf_1.SignPdfError.TYPE_PARSE);
            }
            var byteRangeEnd = pdfString.indexOf("]", byteRangePos);
            if (byteRangeEnd == -1) {
                throw new node_signpdf_1.SignPdfError("Failed to locate the end of the ByteRange.", node_signpdf_1.SignPdfError.TYPE_PARSE);
            }
            var byteRange = pdfString.slice(byteRangePos, byteRangeEnd + 1).toString();
            var matches = (/\/ByteRange \[(\d+) +(\d+) +(\d+) +(\d+) *\]/).exec(byteRange);
            if (matches == null) {
                throw new node_signpdf_1.SignPdfError("Failed to parse the ByteRange.", node_signpdf_1.SignPdfError.TYPE_PARSE);
            }
            var ByteRange = matches.slice(1).map(Number);
            var signedData = Buffer.concat([
                pdfBuffer.slice(ByteRange[0], ByteRange[0] + ByteRange[1]),
                pdfBuffer.slice(ByteRange[2], ByteRange[2] + ByteRange[3]),
            ]);
            var jwt = pdfBuffer.slice(ByteRange[0] + ByteRange[1] + 1, ByteRange[2])
                .toString().replace(/(?:00|>)+$/, "").slice(0, -1);
            signatures[index] = { jwt: jwt, signedData: signedData };
        }
        return signatures;
    };
    PdfJwtVerifier.getSubstringIndex = function (pdf, substring, n) {
        var times = 0, index = null;
        while (times < n && index !== -1) {
            index = pdf.indexOf(substring, index + 1);
            times++;
        }
        return index;
    };
    return PdfJwtVerifier;
}());
exports.PdfJwtVerifier = PdfJwtVerifier;
