package javax.crypto

import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.Key
import java.security.Provider
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec

abstract class CipherSpi {}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/Cipher.html
 */
abstract class Cipher protected (
    spi: CipherSpi,
    provider: Provider,
    transformation: String
) {

  final def getProvider(): Provider = provider

  final def getAlgorithm(): String = transformation

  def getBlockSize(): Int = ???

  def getOutputSize(inputLen: Int): Int = ???

  def getIV(): Array[Byte] = ???

  def getParameters(): AlgorithmParameters = ???

  // not supported yet
  // def getExemptionMechanism(): ExemptionMechanism = ???

  def init(opmode: Int, key: Key): Unit = ???

  def init(opmode: Int, key: Key, random: SecureRandom): Unit = ???

  def init(opmode: Int, key: Key, params: AlgorithmParameterSpec): Unit = ???

  def init(
      opmode: Int,
      key: Key,
      params: AlgorithmParameterSpec,
      random: SecureRandom
  ): Unit = ???

  def init(opmode: Int, key: Key, params: AlgorithmParameters): Unit = ???

  def init(
      opmode: Int,
      key: Key,
      params: AlgorithmParameters,
      random: SecureRandom
  ): Unit = ???

  def init(opmode: Int, certificate: Certificate): Unit = ???

  def init(opmode: Int, certificate: Certificate, random: SecureRandom): Unit =
    ???

  def update(input: Array[Byte]): Array[Byte] = ???

  def update(input: Array[Byte], inputOffset: Int, inputLen: Int): Array[Byte] =
    ???

  def update(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte]
  ): Int = ???

  def update(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte],
      outputOffset: Int
  ): Int = ???

  def update(input: ByteBuffer, output: ByteBuffer): Int = ???

  def doFinal(): Array[Byte] = ???

  def doFinal(output: Array[Byte], outputOffset: Int): Int = ???

  def doFinal(input: Array[Byte]): Array[Byte] = ???

  def doFinal(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int
  ): Array[Byte] = ???

  def doFinal(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte]
  ): Int = ???

  def doFinal(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int,
      output: Array[Byte],
      outputOffset: Int
  ): Int = ???

  def doFinal(input: ByteBuffer, output: ByteBuffer): Int = ???

  def wrap(key: Key): Array[Byte] = ???

  def unwrap(
      wrappedKey: Array[Byte],
      wrappedKeyAlgorithm: String,
      wrappedKeyType: Int
  ): Key = ???

  def updateAAD(src: Array[Byte]): Unit = ???

  def updateAAD(src: Array[Byte], offset: Int, len: Int): Unit = ???

  def updateAAD(src: ByteBuffer): Unit = ???

  override def toString(): String = ???
}

object Cipher {
  // magic numbers come from
  // https://docs.oracle.com/en/java/javase/25/docs/api/constant-values.html
  final val ENCRYPT_MODE: Int = 1
  final val DECRYPT_MODE: Int = 2
  final val WRAP_MODE: Int = 3
  final val UNWRAP_MODE: Int = 4
  final val PUBLIC_KEY: Int = 1
  final val PRIVATE_KEY: Int = 2
  final val SECRET_KEY: Int = 3

  def getInstance(transformation: String): Cipher = ???

  def getInstance(transformation: String, provider: String): Cipher = ???

  def getInstance(transformation: String, provider: Provider): Cipher = ???

  def getMaxAllowedKeyLength(transformation: String): Int = ???

  def getMaxAllowedParameterSpec(
      transformation: String
  ): AlgorithmParameterSpec = ???
}
