import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:at_commons/at_commons.dart';
import 'package:at_data_signing/service/at_data_signing.dart';
import 'package:at_data_signing/util/exceptions.dart';
import 'package:at_data_signing/util/sign_for_type.dart';
import 'package:at_data_signing/util/signature.dart';
import 'package:at_data_signing/util/signature_input.dart';
import 'package:at_data_signing/util/signature_output.dart';
import 'package:at_data_signing/util/signature_verification_result.dart';
import 'package:at_data_signing/util/verified_by.dart';
import 'package:at_utils/at_utils.dart';
import 'package:crypton/crypton.dart';

class AtDataSigningImpl implements AtDataSigning {
  AtSignLogger logger = AtSignLogger('AtDataSigning');
  @override
  // AtValue signAtData(AtValue atValue, String privateKey, String publicKey) {
  //   RSAPrivateKey rsaKey = RSAPrivateKey.fromString(privateKey);
  //   Map<String, String> signatureMap = HashMap<String, String>();
  //   signatureMap[SignForType.clearText.name] =
  //       _getSignature(atValue.value, rsaKey).toString();
  //   signatureMap[SignForType.cipherText.name] =
  //       _getSignature(atValue.value, rsaKey).toString();
  //   atValue.metadata?.dataSignature =
  //       base64Encode(utf8.encode(jsonEncode(signatureMap)) as Uint8List);
  //   return atValue;
  // }

  Signature _getSignature(String value, RSAPrivateKey privateKey) {
    var signBase64 = base64Encode(
        privateKey.createSHA512Signature(utf8.encode(value) as Uint8List));
    Signature signature = Signature()
      ..signature = signBase64
      ..algorithm = 'SHA-3/512'
      ..signatureTimestamp = DateTime.now().toUtc();
    return signature;
  }

  String _getStringSignature(
      String data, String privateKey, String algorithm, int digestLength) {
    RSAPrivateKey rsaPrivateKey = RSAPrivateKey.fromString(privateKey);
    return base64Encode(
        rsaPrivateKey.createSHA512Signature(utf8.encode(data) as Uint8List));
  }

  // @override
  // SignatureVerificationResult verifySignature(
  //     AtValue signedAtValue, String verifierAtsign, String verifierPrivateKey,
  //     {String? publicKey}) {
  //   Map<String, dynamic>? signatureMap;
  //   Uint8List? oldFormatSignature;
  //   SignatureVerificationResult result = SignatureVerificationResult();
  //   bool isJsonTypeSign = false;

  //   //ensure dataSignature field is not empty
  //   if (signedAtValue.metadata?.dataSignature == null) {
  //     result.isVerified = false;
  //     result.exception = SignatureNotFound();
  //     return result;
  //   }

  //   //try to decode json into a Map<string, dynamic> format which is used currently.
  //   //
  //   //If that does not work, assume the signature does not use the new convention and
  //   //directly use it without the need of converting into a Signature() object.
  //   //The on Exception case is present to provide backwards compatability.
  //   try {
  //     signatureMap = jsonDecode(
  //         utf8.decode(base64Decode(signedAtValue.metadata!.dataSignature!)));
  //     isJsonTypeSign = true;
  //   } on Exception catch (e) {
  //     logger.finer(e);
  //     oldFormatSignature = base64Decode(signedAtValue.metadata!.dataSignature!);
  //   }

  //   //if isJsonTypeSign is false, it is assumed that the dataSignature does not use Signature() object
  //   //this case is provided for backwards compatability
  //   if (!isJsonTypeSign) {
  //     if (publicKey == null) {
  //       logger.severe(
  //           'PublicKey is not encoded in AtValue.metadata.dataSignature.'
  //           'Since PublicKey is not found, must be provided as method parameter');
  //       result.isVerified = false;
  //       result.exception = PublicKeyNotFound();
  //       return result;
  //     }
  //     result = _verifySignatureInternal(signedAtValue.value,
  //         oldFormatSignature!, publicKey, verifierAtsign, verifierPrivateKey);
  //   }
  //   //if isJsonTypeSign is true, it is assumed that the dataSignature is of type Map<String, dynamic>
  //   else {
  //     //the below for-each snipped converts all the raw signature to Singature() objects
  //     signatureMap?.forEach((key, value) {
  //       if (key != 'publicKey') {
  //         value = Signature.fromJson(value);
  //       }
  //     });
  //     result = _verifySignatureInternal(
  //         signedAtValue.value,
  //         signatureMap![SignForType.clearText],
  //         signatureMap['publicKey'],
  //         verifierAtsign,
  //         verifierPrivateKey);
  //   }

  //   if (!result.isVerified) {
  //     result.exception = SignatureMismatch();
  //   }

  //   return result;
  // }

  SignatureVerificationResult _verifySignatureInternal(
      String data,
      Uint8List signature,
      String publicKey,
      String verifierAtsign,
      String verifierPrivateKey) {
    RSAPublicKey rsaPublicKey = RSAPublicKey.fromString(publicKey);
    return SignatureVerificationResult()
      ..isVerified = rsaPublicKey.verifySHA512Signature(
          utf8.encode(data) as Uint8List, signature)
      ..actualSignature = base64Encode(signature);
  }

  @override
  String signData(
      String data, String privateKey, String algorithm, int digestLength) {
    return _getStringSignature(data, privateKey, algorithm, digestLength);
  }

  @override
  SignatureOutput signAtData(SignatureInput signatureInput) {
    Map<String, String> signatureMap = {};
    Map<SignForType, String> inputs = {};
    if (signatureInput.clearText != null) {
      inputs[SignForType.clearText] = (signatureInput.clearText!);
    }
    if (signatureInput.cipherText != null) {
      inputs[SignForType.cipherText] = (signatureInput.cipherText!);
    }
    if (signatureInput.metaDataAsString != null) {
      inputs[SignForType.metaData] = (signatureInput.metaDataAsString!);
    }
    String signBase64;
    inputs.forEach((key, value) {
      signBase64 = _getStringSignature(value, signatureInput.privateKey,
          signatureInput.algorithm, signatureInput.digestLength);
      signatureMap[key.toString()] = signBase64;
    });
    return SignatureOutput()
      ..signatureMap = signatureMap
      ..signatureTimestamp = DateTime.now().toUtc()
      ..signedBy = signatureInput.signedBy;
  }

  @override
  bool verifySignature(String data, String signature, String publicKey) {
    RSAPublicKey rsaPublicKey = RSAPublicKey.fromString(publicKey);
    return rsaPublicKey.verifySHA512Signature(
        utf8.encode(data) as Uint8List, base64Decode(signature));
  }
}
