enum SignatureAlgorithm { sha2, sha3 }

extension SignatureAlgorithmExtension on SignatureAlgorithm {
  String getAlgorithm(int length) {
    switch (this) {
      case SignatureAlgorithm.sha2:
        return 'SHA-2/$length';
      case SignatureAlgorithm.sha3:
        return 'SHA-3/$length';
    }
  }

  static SignatureSpecification parseString(String raw) {
    switch (raw) {
      case 'SHA-2/256':
        return SignatureSpecification()
          ..algorithm = SignatureAlgorithm.sha2
          ..length = 256;
      case 'SHA-3/256':
        return SignatureSpecification()
          ..algorithm = SignatureAlgorithm.sha3
          ..length = 256;
      case 'SHA-3/512':
        return SignatureSpecification()
          ..algorithm = SignatureAlgorithm.sha3
          ..length = 512;
    }
    return SignatureSpecification()
      ..algorithm = SignatureAlgorithm.sha2
      ..length = 512;
  }
}

class SignatureSpecification {
  late SignatureAlgorithm algorithm;
  late int length;
}
