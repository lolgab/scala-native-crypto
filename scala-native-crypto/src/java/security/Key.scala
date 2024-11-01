package java.security

trait Key {
  def getAlgorithm(): String
  def getEncoded(): Array[Byte]
  def getFormat(): String
}
