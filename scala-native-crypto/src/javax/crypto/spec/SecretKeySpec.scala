package javax.crypto.spec

import java.security.spec.KeySpec
import java.util.Objects.requireNonNull
import java.util.Arrays
import javax.crypto.SecretKey

// ref: https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/SecretKeySpec.html
class SecretKeySpec(
    private val key: Array[Byte],
    private val offset: Int,
    private val len: Int,
    private val algorithm: String
) extends KeySpec
    with SecretKey {

  requireNonNull(key)
  requireNonNull(algorithm)
  require(key.nonEmpty && offset >= 0 && len > 0 && offset + len <= key.length)
  require(algorithm.nonEmpty)

  private lazy val _key: Array[Byte] = key.clone()

  def this(key: Array[Byte], algorithm: String) =
    this(key, 0, key.length, algorithm)

  def getAlgorithm(): String = algorithm

  def getEncoded(): Array[Byte] = _key

  def getFormat(): String = "RAW"

  override def equals(obj: Any): Boolean = obj match {
    case that: SecretKeySpec =>
      algorithm == that.algorithm &&
      Arrays.equals(key, that.key)
    case _ => false
  }

  override def hashCode(): Int =
    algorithm.hashCode() ^ Arrays.hashCode(key)

  def destroy(): Unit = ???

  def isDestroyed(): Boolean = ???

}
