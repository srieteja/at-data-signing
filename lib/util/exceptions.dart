class SignatureNotFound implements Exception {
  String message = 'DataSignature field of MetaData is null';
}

class SignatureMismatch implements Exception {
  String message =
      'DataSignature invalid. Data (or) signature has been modified';
}

class PublicKeyNotFound implements Exception {
  String message =
      'PublicKey not provided, which is required to verify signature';
}

class InvalidArgument implements Exception {
  late String message;
  InvalidArgument(dynamic value) {
    message = '$value is an invalid argument';
  }
}
