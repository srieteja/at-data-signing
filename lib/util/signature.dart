import 'dart:convert';

class Signature {
  late dynamic signature;
  late String algorithm;
  late DateTime signatureTimestamp;

  Map toJson() {
    return {
      'signature': signature,
      'algorithm': algorithm,
      'signatureTimestamp': signatureTimestamp.toIso8601String()
    };
  }

  static Signature fromJson(String jsonString) {
    var jsonDecoded = jsonDecode(jsonString);
    return Signature()
      ..signature = base64Decode(jsonDecoded['signature'])
      ..algorithm = jsonDecoded['algorithm']
      ..signatureTimestamp = DateTime.parse(jsonDecoded['signatureTimestamp']);
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
