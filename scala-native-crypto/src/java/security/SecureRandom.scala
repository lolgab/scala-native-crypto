package java.security

import scala.scalanative.unsafe._

class SecureRandom() extends java.util.Random(0L) {

  override def setSeed(x: Long): Unit = ()

  override def nextBytes(bytes: Array[Byte]): Unit = Zone { implicit z =>
    val len = bytes.length
    val buffer = alloc[Byte](len)
    if (crypto.RAND_bytes(buffer, len) < 0)
      throw new GeneralSecurityException("Failed to generate random bytes")

    var i = 0
    while (i < len) {
      bytes(i) = buffer(i)
      i += 1
    }
  }

}
