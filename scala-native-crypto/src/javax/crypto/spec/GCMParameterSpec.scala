package javax.crypto.spec

import java.security.spec.AlgorithmParameterSpec

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html
 */
class GCMParameterSpec(
    private val tLen: Int,
    private val src: Array[Byte],
    private val offset: Int,
    private val len: Int
) extends AlgorithmParameterSpec {

  if (src == null)
    throw new IllegalArgumentException("src array is null")
  if (tLen < 0)
    throw new IllegalArgumentException("Invalid tag length")
  if (offset < 0 || len < 0 || offset + len > src.length)
    throw new ArrayIndexOutOfBoundsException("Invalid offset/length")

  private val iv: Array[Byte] = {
    val arr = new Array[Byte](len)
    System.arraycopy(src, offset, arr, 0, len)
    arr
  }

  def this(tLen: Int, src: Array[Byte]) =
    this(tLen, src, 0, if (src == null) 0 else src.length)

  def getTLen(): Int = tLen

  def getIV(): Array[Byte] = iv.clone()
}
