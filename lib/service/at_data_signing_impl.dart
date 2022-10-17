import 'dart:convert';
import 'dart:typed_data';
import 'package:at_data_signing/service/at_data_signing.dart';
import 'package:at_data_signing/util/exceptions.dart';
import 'package:at_data_signing/util/signature_input.dart';
import 'package:at_data_signing/util/signature.dart' as local;
import 'package:at_data_signing/util/signature_algorithm.dart';
import 'package:at_data_signing/util/signature_verification_result.dart';
import 'package:crypton/crypton.dart' as crypton;
import 'package:pointycastle/export.dart';

class AtDataSigningImpl implements AtDataSigning {
  @override
  String signString(String data, String privateKey,
      SignatureAlgorithm algorithm, int digestLength) {
    return _getSignatureInteral(data, privateKey, algorithm, digestLength);
  }

  @override
  local.Signature signWithObject(SignatureInput signatureInput) {
    String signBase64 = _getSignatureInteral(
        signatureInput.textToSign,
        signatureInput.privateKey,
        signatureInput.algorithm,
        signatureInput.digestLength);

    return local.Signature()
      ..actualText = signatureInput.textToSign
      ..signature = signBase64
      ..signatureTimestamp = DateTime.now().toUtc()
      ..signedBy = signatureInput.signedBy
      ..signatureSpecification =
          signatureInput.algorithm.getAlgorithm(signatureInput.digestLength);
  }

  @override
  bool verifySignature(String data, String signature, String publicKey,
      SignatureAlgorithm algorithm, int digestLength) {
    return _verifySignatureInternal(
        data, signature, publicKey, algorithm, digestLength);
  }

  @override
  SignatureVerificationResult verifySignatureObj(
      local.Signature signature, String publicKey) {
    SignatureSpecification spec = SignatureAlgorithmExtension.parseString(
        signature.signatureSpecification);
    SignatureVerificationResult result = SignatureVerificationResult();
    result.isVerified = _verifySignatureInternal(signature.actualText,
        signature.signature, publicKey, spec.algorithm, spec.length);
    result.actualSignature = signature.signature;
    result.exception = SignatureMismatch();
    return result;
  }

  ///Method that formats input parameters from [signString] and [signWithObject] and calls [_generateRsaSign]
  String _getSignatureInteral(String data, String privateKey,
      SignatureAlgorithm algorithm, int digestLength) {
    _verifyDigestLength(digestLength);
    RSAPrivateKey rsaPrivateKey =
        crypton.RSAPrivateKey.fromString(privateKey).asPointyCastle;
    return base64Encode(_generateRsaSign(rsaPrivateKey,
        utf8.encode(data) as Uint8List, _getSigner(algorithm, digestLength)));
  }

  ///Method that formats input parameters from [verifySignature] and [verifySignatureObj] and calls [_verifyRsaSignature]
  bool _verifySignatureInternal(String data, String signature, String publicKey,
      SignatureAlgorithm algorithm, int digestLength) {
    _verifyDigestLength(digestLength);
    RSAPublicKey rsaPublicKey =
        crypton.RSAPublicKey.fromString(publicKey).asPointyCastle;
    return _verifyRsaSignature(
        rsaPublicKey,
        utf8.encode(signature) as Uint8List,
        utf8.encode(data) as Uint8List,
        _getSigner(algorithm, digestLength));
  }

  ///selects a [RSASigner] object based on [SignatureAlgorithm] and [digestLength]
  RSASigner _getSigner(SignatureAlgorithm algorithm, int digestLength) {
    if (algorithm == SignatureAlgorithm.sha2 && digestLength == 256) {
      return RSASigner(SHA256Digest(), '0609608648016503040201');
    } else if (algorithm == SignatureAlgorithm.sha2 && digestLength == 512) {
      return RSASigner(SHA512Digest(), '0609608648016503040203');
    } else if (algorithm == SignatureAlgorithm.sha3 && digestLength == 256) {
      return RSASigner(SHA256Digest(), '0609608648016503040201');
    }
    return RSASigner(SHA512Digest(), '0609608648016503040203');
  }

  ///Actual logic to generate an RSASignature using [RSAPrivateKey]
  Uint8List _generateRsaSign(
      RSAPrivateKey privateKey, Uint8List dataToSign, RSASigner signer) {
    //init RSASigner with forSigning=trure to sign data
    signer.init(true, PrivateKeyParameter<PrivateKey>(privateKey));
    return signer.generateSignature(dataToSign) as Uint8List;
  }

  ///Actual logic to verify [RSASignature] with [data] using [RSAPublicKey]
  bool _verifyRsaSignature(RSAPublicKey publicKey, Uint8List signature,
      Uint8List data, RSASigner verifier) {
    final sign = RSASignature(signature);
    //init RSASigner object with forSigning=false to verify signature
    verifier.init(false, PublicKeyParameter<PublicKey>(publicKey));
    try {
      return verifier.verifySignature(data, sign);
    } on ArgumentError {
      return false;
    }
  }

  ///Method that ensures that the digestLength input to any caller method is 256/512
  void _verifyDigestLength(int length) {
    if (length != 256 && length != 512) {
      throw InvalidArgument(length);
    }
  }
}
