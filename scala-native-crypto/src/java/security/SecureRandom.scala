package java.security

import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._

class SecureRandom() extends java.util.Random(0L) {

  override def setSeed(x: Long): Unit = ()

  override def nextBytes(bytes: Array[Byte]): Unit = {
    val len = bytes.length
    nextBytes(bytes.asInstanceOf[ByteArray].at(0), len)
  }

  private def nextBytes(bytes: Ptr[Byte], len: Int): Unit = {
    if (crypto.RAND_bytes(bytes, len) < 0)
      throw new GeneralSecurityException("Failed to generate random bytes")
  }

}
