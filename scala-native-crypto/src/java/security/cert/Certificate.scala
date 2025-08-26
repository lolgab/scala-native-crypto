package java.security.cert

import java.io.{ByteArrayInputStream, Serializable}
import java.io.NotSerializableException
import java.security.Provider
import java.security.PublicKey

abstract class Certificate(certType: String) extends Serializable {

  final def getType: String = certType

  def getEncoded(): Array[Byte]

  def verify(key: PublicKey): Unit

  def verify(key: PublicKey, sigProvider: String): Unit

  def verify(key: PublicKey, sigProvider: Provider): Unit

  def getPublicKey(): PublicKey

  protected class CertificateRep(certType: String, data: Array[Byte])
      extends Serializable {

    private val repType: String = certType
    private val repData: Array[Byte] = data

    protected def readResolve(): Object = {
      try {
        val cf = CertificateFactory.getInstance(repType)
        cf.generateCertificate(new ByteArrayInputStream(repData))
      } catch {
        case e: CertificateException =>
          throw new NotSerializableException(
            s"java.security.cert.Certificate: ${repType}: ${e.getMessage}"
          )
      }
    }
  }

  protected def writeReplace(): Object = {
    try {
      new CertificateRep(certType, getEncoded())
    } catch {
      case e: CertificateException =>
        throw new NotSerializableException(
          s"java.security.cert.Certificate: ${certType}: ${e.getMessage}"
        )
    }
  }

  override def toString: String = {
    ???
  }

  override def equals(other: Any): Boolean = {

    ???
  }

  override def hashCode(): Int = {
    ???
  }

}
