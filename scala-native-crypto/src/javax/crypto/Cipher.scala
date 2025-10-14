package javax.crypto

import java.nio.{ByteBuffer, ReadOnlyBufferException}

import java.security.{
  AlgorithmParameters,
  ExemptionMechanism,
  Key,
  SecureRandom
}
import java.security.Provider.Service
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.{List => JList, Map => JMap, Set => JSet}

class Cipher protected (
    private val spi: CipherSpi,
    private val provider: Provider,
    private val transformation: String
) {

  def getProvider(): Provider = ???

  def getAlgorithm(): String = ???

  def getBlockSize(): Int = ???

  def getOutputSize(inputLen: Int): Int = ???

  def getIV(): Array[Byte] = ???

  def getParameters(): AlgorithmParameters = ???

  def getExemptionMechanism(): ExemptionMechanism = ???

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
