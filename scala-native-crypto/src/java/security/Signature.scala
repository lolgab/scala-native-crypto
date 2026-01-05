package java.security

import java.nio.ByteBuffer
import java.security.Provider
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Objects.requireNonNull

abstract class SignatureSpi {}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/Signature.html
 */
abstract class Signature(
    spi: SignatureSpi,
    provider: Provider,
    algorithm: String
) {

  // magic numbers come from
  // https://docs.oracle.com/en/java/javase/25/docs/api/constant-values.html#java.security
  protected val UNINITIALIZED = 0
  protected val SIGN = 2
  protected val VERIFY = 3

  @volatile protected var state = UNINITIALIZED

  final def getProvider(): Provider = provider

  def initVerify(publicKey: PublicKey): Unit

  def initVerify(certificate: Certificate): Unit

  def initSign(privateKey: PrivateKey): Unit

  def initSign(privateKey: PrivateKey, random: SecureRandom): Unit

  def sign(): Array[Byte]

  def sign(outbuf: Array[Byte], off: Int, len: Int): Int

  def verify(sig: Array[Byte]): Boolean

  def verify(sig: Array[Byte], off: Int, len: Int): Boolean

  def update(b: Byte): Unit

  final def update(data: Array[Byte]): Unit = update(data, 0, data.length)

  def update(data: Array[Byte], off: Int, len: Int): Unit

  def update(data: ByteBuffer): Unit

  final def getAlgorithm(): String = algorithm

  override def toString: String = {
    val s = state match {
      case UNINITIALIZED => "<not initialized>"
      case VERIFY        => "<initialized for verifying>"
      case SIGN          => "<initialized for signing>"
      case _             => ""
    }
    s"Signature object: ${algorithm} ${s}"
  }

  @deprecated
  final def setParameter(param: String, value: Object): Unit =
    throw new UnsupportedOperationException(
      "setParameter(String, Object) not supported"
    )

  def setParameter(params: AlgorithmParameterSpec): Unit

  def getParameters(): AlgorithmParameters
}

object Signature {

  def getInstance(algorithm: String): Signature = {
    requireNonNull(algorithm)
    require(algorithm.nonEmpty)

    ???
  }

  def getInstance(algorithm: String, provider: String): Signature =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): Signature = {
    requireNonNull(algorithm)
    requireNonNull(provider)
    require(algorithm.nonEmpty)

    ???
  }

}
