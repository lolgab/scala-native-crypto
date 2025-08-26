package java.security.spec

import java.security.DEREncodable

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/PKCS8EncodedKeySpec.html
class PKCS8EncodedKeySpec(
    encodedKey: Array[Byte],
    algorithm: String
) extends EncodedKeySpec(encodedKey, algorithm)
    with DEREncodable {
  final def getFormat(): String = "PKCS#8"
}
