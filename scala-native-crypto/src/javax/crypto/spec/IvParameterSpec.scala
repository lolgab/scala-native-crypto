package javax.crypto.spec

import java.security.spec.AlgorithmParameterSpec

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html
 */
class IvParameterSpec(
    private val src: Array[Byte],
    private val offset: Int,
    private val len: Int
) extends AlgorithmParameterSpec {

  if (src == null)
    throw new IllegalArgumentException("IV array is null")
  if (offset < 0 || len < 0 || offset + len > src.length)
    throw new ArrayIndexOutOfBoundsException("Invalid offset/length")

  private val iv: Array[Byte] = {
    val arr = new Array[Byte](len)
    System.arraycopy(src, offset, arr, 0, len)
    arr
  }

  def this(iv: Array[Byte]) =
    this(iv, 0, if (iv == null) 0 else iv.length)

  def getIV(): Array[Byte] = iv.clone()
}
