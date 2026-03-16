package javax.security.auth.x500

import java.io.Serializable
import java.util.{Map => JMap}
import java.security.Principal
import java.io.InputStream

// Refs:
// 1. https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/security/auth/x500/X500Principal.html
class X500Principal extends Principal with Serializable {

  def this(name: Array[Byte]) = this()

  def this(is: InputStream) = this()

  def this(name: String) = this()

  def this(name: String, keywordMap: JMap[String, String]) = this()

  def getName(): String =
    getName(X500Principal.RFC2253)

  def getName(format: String): String = ???

  def getName(format: String, oidMap: JMap[String, String]): String = ???

  def getEncoded(): Array[Byte] = ???

  override def toString(): String = ???

  override def equals(other: Any): Boolean = ???

  override def hashCode(): Int = ???
}

object X500Principal {
  final val CANONICAL: String = "CANONICAL"
  final val RFC1779: String = "RFC1779"
  final val RFC2253: String = "RFC2253"
}
