package java.security

import java.security.spec.AlgorithmParameterSpec
import java.security.{Provider, SecureRandom}

/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyPairGenerator.html
abstract class KeyPairGenerator protected (
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

  def getInstance(algorithm: String, provider: String): KeyPairGenerator = ???

  def getInstance(algorithm: String, provider: Provider): KeyPairGenerator = ???

}
