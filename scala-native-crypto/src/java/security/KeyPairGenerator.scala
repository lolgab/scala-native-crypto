package java.security

import java.security.Provider
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec

abstract class KeyPairGeneratorSpi {}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyPairGenerator.html
 */
abstract class KeyPairGenerator(
    spi: KeyPairGeneratorSpi,
    provider: Provider,
    algorithm: String
) {

  final def getAlgorithm(): String = algorithm

  final def getProvider(): Provider = provider

  def initialize(keysize: Int): Unit

  def initialize(keysize: Int, random: SecureRandom): Unit

  def initialize(param: AlgorithmParameterSpec): Unit

  def initialize(
      param: AlgorithmParameterSpec,
      random: SecureRandom
  ): Unit

  final def genKeyPair(): KeyPair = generateKeyPair()

  def generateKeyPair(): KeyPair

}

object KeyPairGenerator {

  def getInstance(algorithm: String): KeyPairGenerator = ???

  def getInstance(algorithm: String, provider: String): KeyPairGenerator =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): KeyPairGenerator = ???

}
