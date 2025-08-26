package java.security.spec

import java.security.DEREncodable

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/X509EncodedKeySpec.html
// @since JDK 9
class X509EncodedKeySpec(
    encodedKey: Array[Byte],
    algorithm: String
) extends EncodedKeySpec(encodedKey, algorithm)
    with DEREncodable {
  final def getFormat(): String = "X.509"
}
