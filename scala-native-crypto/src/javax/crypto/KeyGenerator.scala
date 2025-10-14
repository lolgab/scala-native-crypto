package javax.crypto

import java.security.{Provider, SecureRandom}
import java.security.{
  InvalidAlgorithmParameterException,
  InvalidParameterException,
  NoSuchAlgorithmException,
  NoSuchProviderException
}
import java.security.spec.AlgorithmParameterSpec

// Refs:
//
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/KeyGenerator.html
class KeyGenerator protected (
    // keyGenSpi: KeyGeneratorSpi,
    provider: Provider,
    algorithm: String
) {

  def getAlgorithm(): String = {
    ???
  }

  def getProvider(): Provider = {
    ???
  }

  def init(random: SecureRandom): Unit = {
    ???
  }

  def init(params: AlgorithmParameterSpec): Unit = {
    ???
  }

  def init(
      params: AlgorithmParameterSpec,
      random: SecureRandom
  ): Unit = {
    ???
  }

  def init(keysize: Int): Unit = {
    ???
  }

  def init(keysize: Int, random: SecureRandom): Unit = {
    ???
  }

  def generateKey(): SecretKey = {
    ???
  }
}

object KeyGenerator {

  def getInstance(algorithm: String): KeyGenerator = {
    ???
  }

  def getInstance(algorithm: String, provider: String): KeyGenerator = {
    ???
  }

  def getInstance(
      algorithm: String,
      provider: Provider
  ): KeyGenerator = {
    ???
  }
}
