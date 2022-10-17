class SignatureVerificationResult {
  late bool isVerified;
  String? expectedSignature;
  String? actualSignature;
  Exception? exception;

  @override
  String toString() {
    return 'isVerified: $isVerified, expectedSignature: $expectedSignature, actualSignature: $actualSignature';
  }
}
