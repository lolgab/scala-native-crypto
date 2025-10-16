package java.security

import java.util.Objects.requireNonNull
import java.security.spec.KeySpec
import java.security.spec.InvalidKeySpecException

/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyFactory.html
class KeyFactory protected (
    private val provider: Provider,
    private val algorithm: String
) {
  requireNonNull(provider)
  requireNonNull(algorithm)
  require(
    algorithm == null || algorithm.nonEmpty,
    "algorithm could be null otherwise cannot be empty if not null"
  )

  final def generatePrivate(is: KeySpec): PrivateKey = ???

  final def generatePublic(is: KeySpec): PublicKey = ???

  final def getKeySpec[T <: KeySpec](key: Key, spec: Class[T]): T = {
    requireNonNull(key)
    requireNonNull(spec)
    if (!spec.isAssignableFrom(classOf[KeySpec]))
      throw new InvalidKeySpecException(
        "Unsupported key specification: " + spec
      )
    ???
  }

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  final def translateKey(key: Key): Key = {
    requireNonNull(key)
    if (key.getAlgorithm() != algorithm)
      throw new InvalidKeyException("Wrong key type")
    ???
  }
}

object KeyFactory {
  def getInstance(algorithm: String): KeyFactory = ???

  def getInstance(algorithm: String, provider: String): KeyFactory = ???

  def getInstance(algorithm: String, provider: Provider): KeyFactory = ???
}
