package java.security

import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._

class SecureRandom() extends java.util.Random(0L) {

  override def setSeed(x: Long): Unit = ()

  override def nextBytes(bytes: Array[Byte]): Unit = {
    val len = bytes.length
    (bytes: Any) match {
      case ba: ByteArray =>
        nextBytes(ba.at(0), len)
      case _ =>
        Zone { implicit z =>
          val buffer = alloc[Byte](len)
          nextBytes(buffer, len)
          var i = 0
          while (i < len) {
            bytes(i) = buffer(i)
            i += 1
          }
        }
    }

  }

  private def nextBytes(bytes: Ptr[Byte], len: Int): Unit = {
    if (crypto.RAND_bytes(bytes, len) < 0)
      throw new GeneralSecurityException("Failed to generate random bytes")
  }

}
