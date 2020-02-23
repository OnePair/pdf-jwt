export class InvalidSignatureError extends Error {
  constructor(reason: string) {
    super(reason);
  }
}
