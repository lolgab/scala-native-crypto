package java.security

abstract class Signature
object Signature {
  def getInstance(algorithm: String): Signature =
    throw new NotImplementedError("Not implemented yet")
}
