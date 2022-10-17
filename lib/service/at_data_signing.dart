import 'package:at_data_signing/util/signature_algorithm.dart';
import 'package:at_data_signing/util/signature_input.dart';
import 'package:at_data_signing/util/signature.dart';
import 'package:at_data_signing/util/signature_verification_result.dart';

///Abstract class defining methods for signing and signature-veridying [AtValue]
abstract class AtDataSigning {
  ///Method that generates dataSignature for String [data] using an [RSAPrivateKey]
  ///
  ///Required Inputs:
  ///
  /// 1) String data that needs to be signed
  /// 2) [privateKey] of type RSAPrivateKey in a string format
  /// 3) Preferred algorithm to generate signature. Choose from algorithms specified in [SignatureAlgorithm]
  /// 4) Preffered length of signature
  ///
  ///Output: base64Encoded signature generated using [algorithm] and [digestLength]
  String signString(String data, String privateKey,
      SignatureAlgorithm algorithm, int digestLength);

  ///Method that generates dataSignature for type[SignatureInput] using an [RSAPrivateKey]
  ///
  ///Required Inputs:
  ///
  /// 1) [SignatureInput] object with all parameters specified
  ///
  ///Output:
  ///
  ///[Signature] object containing [signature], [signatureTimestamp] and [signedBy]
  ///signature is a base64Encoded String generated using algoritm and digestLength specified in [SignatureInput]
  Signature signWithObject(SignatureInput signatureInput);

  //////Verifies dataSignature in [data] to [signature] using [publicKey]
  ///
  ///Required inputs:
  ///1) data that needs to be verified using [signature]
  ///2) signature to be verified in base64Encoded String format
  ///3) publicKey of type [RSAPublicKey] belonging to the [RSAKeyPair] whose privateKey was used to generate signature
  ///4) Algorithm used to generate [signature]
  ///5) DigestLength used to generate [signature]
  ///
  ///Output:
  ///
  ///Case verified - Returns [SignatureVerificationResult] object with [SignatureVerificationResult.isVerified] set to true
  ///
  ///case NotVerified - Returns [SignatureVerificationResult] object with [SignatureVerificationResult.isVerified] set to false
  ///and the exception is stored in [SignatureVerificationResult.exception]
  // SignatureVerificationResult verifySignature(
  //     AtValue signedAtData, String verifierAtsign, String verifierPrivateKey);

  bool verifySignature(String data, String signature, String publicKey,
      SignatureAlgorithm algorithm, int digestLength);

  ///Method that verifies dataSignature of object type [Signature] using [RSAPublicKey]
  ///
  ///Required inputs:
  ///1) [Signature] object containing all required parameters
  ///2) publicKey of type [RSAPublicKey] belonging to the [RSAKeyPair] whose privateKey was used to generate signature
  ///
  ///Verifies signature in [Signature.signature] to [Signature.actualText]
  ///
  ///Output:
  ///
  ///Case verified - Returns [SignatureVerificationResult] object with [SignatureVerificationResult.isVerified] set to true
  ///
  ///case NotVerified - Returns [SignatureVerificationResult] object with [SignatureVerificationResult.isVerified] set to false
  ///and the exception is stored in [SignatureVerificationResult.exception]
  // SignatureVerificationResult verifySignature(
  //     AtValue signedAtData, String verifierAtsign, String verifierPrivateKey);
  SignatureVerificationResult verifySignatureObj(
      Signature signature, String publicKey);
}
