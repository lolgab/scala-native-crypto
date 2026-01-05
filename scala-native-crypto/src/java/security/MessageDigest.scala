package java.security

import java.security.Provider
import java.util.Objects.requireNonNull

abstract class MessageDigestSpi

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/MessageDigest.html
 */
abstract class MessageDigest(
    spi: MessageDigestSpi,
    provider: Provider,
    algorithm: String
) {

  final def getProvider(): Provider = provider

  def update(input: Byte): Unit

  def update(input: Array[Byte], offset: Int, len: Int): Unit

  def update(input: Array[Byte]): Unit

  def digest(): Array[Byte]

  def digest(buf: Array[Byte], offset: Int, len: Int): Int

  def digest(input: Array[Byte]): Array[Byte]

  override def toString(): String = ???

  // mark as ??? for compilation now, should be implemented
  def isEqual(digesta: Array[Byte], digestb: Array[Byte]): Boolean = ???

  def reset(): Unit

  final def getAlgorithm(): String = algorithm

  def getDigestLength(): Int

}

object MessageDigest {
  import com.github.lolgab.scalanativecrypto.{OpenSslProvider, JcaService}

  def getInstance(algorithm: String): MessageDigest = getInstance(
    algorithm,
    OpenSslProvider.defaultInstance
  )

  def getInstance(algorithm: String, provider: String): MessageDigest =
    throw new UnsupportedOperationException()

  def getInstance(algorithm: String, provider: Provider): MessageDigest = {
    requireNonNull(provider)
    requireNonNull(algorithm)
    require(algorithm.nonEmpty)

    val service = provider.getService(JcaService.MessageDigest.name, algorithm)
    if (service == null)
      throw new NoSuchAlgorithmException(
        s"Algorithm $algorithm not found in provider ${provider.getName()}"
      )
    service.newInstance(null).asInstanceOf[MessageDigest]
  }
}
