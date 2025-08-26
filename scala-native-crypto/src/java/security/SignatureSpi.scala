package java.security

import java.nio.ByteBuffer
import java.security.spec.AlgorithmParameterSpec

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/SignatureSpi.html
abstract class SignatureSpi {

  @volatile protected var appRandom: SecureRandom = null

  override def clone(): Object =
    if (this.isInstanceOf[Cloneable]) super.clone()
    else throw CloneNotSupportedException()

  // @deprecated
  // protected def engineGetParameter(param: String): Object

  protected def engineGetParameters(): AlgorithmParameters = ???

  protected def engineInitSign(privateKey: PrivateKey): Unit

  protected def engineInitSign(
      privateKey: PrivateKey,
      random: SecureRandom
  ): Unit = {
    appRandom = random
    engineInitSign(privateKey)
  }

  protected def engineInitVerify(publicKey: PublicKey): Unit

  // @deprecated
  // protected def engineSetParameter(param: String, value: Object): Unit

  protected def engineSetParameter(params: AlgorithmParameterSpec): Unit

  protected def engineSign(): Array[Byte]

  protected final def engineSign(
      outbuf: Array[Byte],
      offset: Int,
      len: Int
  ): Int = {
    val sig = engineSign()

    if (len < sig.length)
      throw SignatureException("partial signatures not returned")
    if ((outbuf.length - offset) < sig.length)
      throw SignatureException(
        "insufficient space in the output buffer to store the signature"
      )

    Array.copy(sig, 0, outbuf, offset, sig.length)
    sig.length
  }

  protected def engineUpdate(b: Byte): Unit

  protected def engineUpdate(b: Array[Byte], off: Int, len: Int): Unit

  protected def engineUpdate(input: ByteBuffer): Unit = {
    if (!input.hasRemaining) return

    try {
      //   if (input.hasArray) {
      //     val b = input.array
      //     val ofs = input.arrayOffset
      //     val pos = input.position
      //     val lim = input.limit
      //     engineUpdate(b, ofs + pos, lim - pos)
      //     input.position(lim)
      //   } else {
      //     var len = input.remaining
      //     val b = new Array[Byte](Math.min(len, 4096))
      //     while (len > 0) {
      //       val chunk = Math.min(len, b.length)
      //       input.get(b, 0, chunk)
      //       engineUpdate(b, 0, chunk)
      //       len -= chunk
      //     }
      //   }
      ???
    } catch {
      case exc: Exception =>
        throw SignatureException(
          "this signature algorithm is unable to process the input data provided",
          exc
        )
    }
  }

  protected def engineVerify(sigBytes: Array[Byte]): Boolean

  protected def engineVerify(
      sigBytes: Array[Byte],
      offset: Int,
      length: Int
  ): Boolean = {
    val sigBytesCopy = new Array[Byte](length)
    Array.copy(sigBytes, offset, sigBytesCopy, 0, length)
    engineVerify(sigBytesCopy)
  }

}
