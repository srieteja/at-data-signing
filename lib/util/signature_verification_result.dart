import 'package:at_data_signing/util/signature.dart';
import 'package:at_data_signing/util/verified_by.dart';

class SignatureVerificationResult {
  late bool isVerified;
  List<VerifiedBy> verifiedBy = [];
  String? expectedSignature;
  String? actualSignature;
  Exception? exception;

  @override
  String toString() {
    return 'isVerified: $isVerified, verifiedBy: $verifiedBy, expectedSignature: $expectedSignature, actualSignature: $actualSignature';
  }
}
