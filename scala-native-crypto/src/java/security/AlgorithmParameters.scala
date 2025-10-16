package java.security

import java.security.spec.AlgorithmParameterSpec
import java.util.Objects.requireNonNull

/// References:
///
///  - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/AlgorithmParameters.html
abstract class AlgorithmParameters protected (
    // paramSpi: AlgorithmParametersSpi,
    provider: Provider,
    algorithm: String
) {

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  def init(paramSpec: AlgorithmParameterSpec): Unit

  def init(params: Array[Byte]): Unit

  def init(params: Array[Byte], format: String): Unit

  def getParameterSpec[T <: AlgorithmParameterSpec](paramSpec: Class[T]): T

  def getEncoded(): Array[Byte] = ???

  def getEncoded(format: String): Array[Byte]

  override def toString(): String
}

object AlgorithmParameters {

  def getInstance(algorithm: String): AlgorithmParameters = {
    requireNonNull(algorithm)
    require(algorithm.nonEmpty)

    ???
  }

  def getInstance(algorithm: String, provider: String): AlgorithmParameters = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)
    require(provider.nonEmpty)

    ???
  }

  def getInstance(
      algorithm: String,
      provider: Provider
  ): AlgorithmParameters = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)

    ???
  }
}
