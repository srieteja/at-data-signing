import 'package:at_commons/at_commons.dart';
import 'package:at_data_signing/util/signature_input.dart';
import 'package:at_data_signing/util/signature_output.dart';
import 'package:at_data_signing/util/signature_verification_result.dart';

///Abstract class defining methods for signing and signature-veridying [AtValue]
abstract class AtDataSigning {
  ///Method to create dataSignature for type[AtValue] using an [RSAPrivateKey]
  ///
  ///Required Inputs:
  ///
  /// 1) object of type [AtValue]
  /// 2) [privateKey] of type RSAPrivateKey in a string format
  /// 3) [publicKey] belonging to the keypair whose private key is used to create the signature
  ///
  ///Signature is of type [Map<String, Signature>] mapping [SignForType] to base64Encoded [SHA3] signature of length 512
  ///
  ///Output: [AtValue] object containing base64Encoded signatureMap stored in [AtValue.metadata.dataSignature]
  String signData(
      String data, String privateKey, String algorithm, int digestLength);

  SignatureOutput signAtData(SignatureInput signatureInput);

  ///Method to verify dataSignature of object type [AtValue] using [RSAPublicKey]
  ///
  ///Required inputs:
  ///1) [AtValue] object containing a dataSignature
  ///2) [verifierAtsign] is the [AtSign] of the user verifying the signature
  ///3) [verifierPrivateKey] is the EncryptionPrivateKey of the verifier which will be used to further sign the data
  ///
  ///Verifies signature in [AtValue.metadata.dataSignature] to [AtValue.value] and [AtValue.metadata]
  ///
  ///Output:
  ///
  ///Case verified - Returns [SignatureVerificationResult] object with [SignatureVerificationResult.isVerified] set to true
  ///
  ///case NotVerified - Returns [SignatureVerificationResult] object with [SignatureVerificationResult.isVerified] set to false
  ///and the exception is stored in [SignatureVerificationResult.exception]
  // SignatureVerificationResult verifySignature(
  //     AtValue signedAtData, String verifierAtsign, String verifierPrivateKey);

  bool verifySignature(String data, String signature, String publicKey);
}
