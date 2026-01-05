package java.security

import java.util.Objects.requireNonNull
import java.security.spec.KeySpec

abstract class KeyFactorySpi

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyFactory.html
 */
abstract class KeyFactory protected (
    spi: KeyFactorySpi,
    provider: Provider,
    algorithm: String
) {
  requireNonNull(provider)
  requireNonNull(algorithm)
  require(
    algorithm == null || algorithm.nonEmpty,
    "algorithm could be null otherwise cannot be empty if not null"
  )

  def generatePrivate(is: KeySpec): PrivateKey

  def generatePublic(is: KeySpec): PublicKey

  def getKeySpec[T <: KeySpec](key: Key, spec: Class[T]): T

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  def translateKey(key: Key): Key
}

object KeyFactory {
  def getInstance(algorithm: String): KeyFactory = ???

  def getInstance(algorithm: String, provider: String): KeyFactory =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): KeyFactory = ???
}
