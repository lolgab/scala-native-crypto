package java.security.cert

import java.io.OutputStream

trait Extension {
  def getId(): String

  def isCritical(): Boolean

  def getValue(): Array[Byte]

  def encode(out: OutputStream): Unit
}
