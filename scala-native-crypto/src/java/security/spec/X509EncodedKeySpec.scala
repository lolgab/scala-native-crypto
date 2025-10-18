package java.security.spec

/// @since JDK 9
///
/// ## Ref
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/spec/X509EncodedKeySpec.html
///
class X509EncodedKeySpec(
    encodedKey: Array[Byte],
    algorithm: String
) extends EncodedKeySpec(encodedKey, algorithm) {
  def this(encodedKey: Array[Byte]) = this(encodedKey, null)

  final def getFormat(): String = "X.509"
}
