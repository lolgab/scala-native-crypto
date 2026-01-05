package javax.crypto

import java.security.{Key, Provider, SecureRandom}
import java.security.spec.AlgorithmParameterSpec

abstract class KeyAgreementSpi {}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/KeyAgreement.html
 */
class KeyAgreement protected (
    keyAgreeSpi: KeyAgreementSpi,
    provider: Provider,
    algorithm: String
) {
  def getAlgorithm(): String = algorithm

  def getProvider(): Provider = ???

  def init(key: Key): Unit = ???

  def init(key: Key, random: SecureRandom): Unit = ???

  def init(key: Key, params: AlgorithmParameterSpec): Unit = ???

  def init(
      key: Key,
      params: AlgorithmParameterSpec,
      random: SecureRandom
  ): Unit = ???

  def doPhase(key: Key, lastPhase: Boolean): Key = ???

  def generateSecret(): Array[Byte] = ???

  def generateSecret(sharedSecret: Array[Byte], offset: Int): Int = ???

  def generateSecret(algorithm: String): SecretKey = ???
}

object KeyAgreement {
  def getInstance(algorithm: String): KeyAgreement = ???

  def getInstance(algorithm: String, provider: String): KeyAgreement =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): KeyAgreement = ???
}
