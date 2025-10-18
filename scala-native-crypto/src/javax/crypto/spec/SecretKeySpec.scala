package javax.crypto.spec

import java.security.spec.KeySpec
import java.util.Arrays
import javax.crypto.SecretKey
import java.util.concurrent.atomic.AtomicBoolean

/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/SecretKeySpec.html
class SecretKeySpec(
    private val key: Array[Byte],
    private val offset: Int,
    private val len: Int,
    private val algorithm: String
) extends KeySpec
    with SecretKey {

  if (key == null || algorithm == null)
    throw new IllegalArgumentException("Missing argument")
  if (key.isEmpty)
    throw new IllegalArgumentException("Empty key")
  if (offset < 0 || len < 0)
    throw new ArrayIndexOutOfBoundsException(
      "offset and length must be non-negative"
    )
  require(offset + len <= key.length, "Invalid offset and length combination")
  require(algorithm.nonEmpty)

  private lazy val _key: Array[Byte] = key.clone()
  private val destroyed: AtomicBoolean = new AtomicBoolean(false)

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
    31 * algorithm.hashCode() ^ Arrays.hashCode(key)

  override def destroy(): Unit =
    if (destroyed.compareAndSet(false, true))
      Arrays.fill(_key, 0.toByte)

  override def isDestroyed(): Boolean = destroyed.getOpaque()
}
