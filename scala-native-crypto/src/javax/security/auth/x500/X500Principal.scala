package javax.security.auth.x500

import java.io.{Serializable, InputStream}
import java.util.{Map => JMap}
import java.security.Principal
import java.util.Collections
import java.util.Objects.requireNonNull

// Refs:
// 1. https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/security/auth/x500/X500Principal.html
// 2. https://www.rfc-editor.org/info/rfc1779
// 3. https://www.rfc-editor.org/info/rfc2253
// 4. https://www.rfc-editor.org/info/rfc5280
final class X500Principal(name: String, keywordMap: JMap[String, String])
    extends Principal
    with Serializable {

  // TODO:
  // verify in RFC 1779 or RFC 2253 format, or throw IllegalArgumentException if not

  def this(is: InputStream) = this(
    {
      requireNonNull(is, "input stream must not be null")
      val data = new Array[Byte](is.available())
      is.read(data)
      throw new UnsupportedOperationException(
        "Constructor(InputStream) is not supported yet"
      )
    },
    Collections.emptyMap[String, String]()
  )

  def this(name: String) = this(
    name,
    Collections.emptyMap[String, String]()
  )

  def this(name: Array[Byte]) = this(
    {
      requireNonNull(name)
      ???
    },
    Collections.emptyMap[String, String]()
  )

  requireNonNull(name, "name must not be null")
  requireNonNull(keywordMap, "keyword map must not be null")

  def getName(): String =
    name // getName(X500Principal.RFC2253)

  def getName(format: String): String =
    ???

  def getName(format: String, oidMap: JMap[String, String]): String =
    ???

  def getEncoded(): Array[Byte] =
    ???

  override def toString(): String =
    ???

  override def equals(other: Any): Boolean =
    other match {
      case that: X500Principal =>
        (this.getName(X500Principal.CANONICAL)
          == that.getName(X500Principal.CANONICAL))
      case _ => false
    }

  override def hashCode(): Int =
    getName(X500Principal.CANONICAL).hashCode()

}

object X500Principal {
  final val CANONICAL: String = "CANONICAL"
  final val RFC1779: String = "RFC1779"
  final val RFC2253: String = "RFC2253"
}
