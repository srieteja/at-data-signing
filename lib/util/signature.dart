import 'package:at_data_signing/at_data_signing.dart';
import 'package:at_data_signing/util/signature_algorithm.dart';

class Signature {
  late String actualText;
  late String signature;
  DateTime? signatureTimestamp;
  String? signedBy;
  late String signatureSpecification;
}
