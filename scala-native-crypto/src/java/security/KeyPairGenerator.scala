package java.security

import java.security.spec.AlgorithmParameterSpec

/// Refs:
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyPairGenerator.html
abstract class KeyPairGenerator protected (algorithm: String) {

  def getAlgorithm(): String = {
    ???
  }

  final def getProvider(): Provider = {
    ???
  }

  def initialize(keysize: Int): Unit = {
    ???
  }

  def initialize(keysize: Int, random: SecureRandom): Unit = {
    ???
  }

  def initialize(param: AlgorithmParameterSpec): Unit = {
    ???
  }

  def initialize(
      param: AlgorithmParameterSpec,
      random: SecureRandom
  ): Unit = {
    ???
  }

  final def genKeyPair(): KeyPair = generateKeyPair()

  def generateKeyPair(): KeyPair = {
    ???
  }

}

object KeyPairGenerator {

  def getInstance(algorithm: String): KeyPairGenerator = {
    ???
  }

  def getInstance(
      algorithm: String,
      provider: String
  ): KeyPairGenerator = {
    ???
  }

  def getInstance(
      algorithm: String,
      provider: Provider
  ): KeyPairGenerator = {
    ???
  }

}
