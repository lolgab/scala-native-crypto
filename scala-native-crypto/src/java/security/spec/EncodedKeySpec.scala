package java.security.spec

/// Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/spec/EncodedKeySpec.html
abstract class EncodedKeySpec protected (
    encodedKey: Array[Byte],
    algorithm: String
) extends KeySpec {

  require(
    algorithm == null || algorithm.nonEmpty,
    "algorithm could be null otherwise cannot be empty if not null"
  )
  private lazy val _encodedKey = encodedKey.clone()

  def this(encodedKey: Array[Byte]) = this(encodedKey, null)

  final def getAlgorithm(): String = algorithm

  final def getEncoded(): Array[Byte] = _encodedKey

  def getFormat(): String

}
