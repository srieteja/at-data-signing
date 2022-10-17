import 'package:at_data_signing/util/signature_algorithm.dart';

class SignatureInput {
  late String textToSign;
  late String privateKey;
  late SignatureAlgorithm algorithm;
  late int digestLength;
  late String signedBy;
}
