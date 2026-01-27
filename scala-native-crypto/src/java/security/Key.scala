package java.security

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/Key.html
 */
trait Key extends Serializable {
  def getAlgorithm(): String

  def getEncoded(): Array[Byte]

  def getFormat(): String
}
