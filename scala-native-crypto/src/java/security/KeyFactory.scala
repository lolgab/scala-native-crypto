package java.security

import java.util.Objects.requireNonNull
import java.security.spec.KeySpec
import java.security.spec.InvalidKeySpecException

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyFactory.html
class KeyFactory protected (
    private val provider: Provider,
    private val algorithm: String
) {
  requireNonNull(provider)
  requireNonNull(algorithm)
  require(algorithm != null && algorithm.nonEmpty)

  final def generatePrivate(is: KeySpec): PrivateKey = {
    ???
  }

  final def generatePublic(is: KeySpec): PublicKey = {
    ???
  }

  final def getKeySpec[T <: KeySpec](key: Key, spec: Class[T]): T = {
    requireNonNull(key)
    requireNonNull(spec)
    if (!spec.isAssignableFrom(classOf[KeySpec]))
      throw new InvalidKeySpecException(
        "Unsupported key specification: " + spec
      )
    throw new NotImplementedError("Not implemented yet")
  }

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  final def translateKey(key: Key): Key = {
    requireNonNull(key)
    if (key.getAlgorithm() != algorithm)
      throw new InvalidKeyException("Wrong key type")
    throw new NotImplementedError("Not implemented yet")
  }
}

object KeyFactory {
  def getInstance(algorithm: String): KeyFactory =
    throw new NotImplementedError("Not implemented yet")

  def getInstance(algorithm: String, provider: String): KeyFactory =
    throw new NotImplementedError("Not implemented yet")

  def getInstance(algorithm: String, provider: Provider): KeyFactory =
    throw new NotImplementedError("Not implemented yet")
}
