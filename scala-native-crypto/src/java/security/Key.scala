package java.security

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/Key.html
trait Key extends Serializable {
  def getAlgorithm(): String
  def getEncoded(): Array[Byte]
  def getFormat(): String
}
