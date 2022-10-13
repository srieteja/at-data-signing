import 'dart:convert';

class VerifiedBy {
  late String atsign;
  late String signature;
  late DateTime signatureTimestamp;

  Map toJson() {
    return {
      'atsign': atsign,
      'signature': signature,
      'signatureTimestamp': signatureTimestamp.toIso8601String()
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
