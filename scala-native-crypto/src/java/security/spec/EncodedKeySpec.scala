package java.security.spec

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/EncodedKeySpec.html
abstract class EncodedKeySpec protected (
    encodedKey: Array[Byte],
    algorithm: String
) extends KeySpec {

  require(algorithm != null && algorithm.nonEmpty)
  private lazy val _encodedKey = encodedKey.clone()

  def this(encodedKey: Array[Byte]) = this(encodedKey, null)

  def getAlgorithm(): String = algorithm

  def getEncoded(): Array[Byte] = _encodedKey

  def getFormat(): String

}
