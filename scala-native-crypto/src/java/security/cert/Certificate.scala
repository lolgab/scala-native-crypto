package java.security.cert

import java.io.ByteArrayInputStream
import java.io.NotSerializableException
import java.security.Provider
import java.security.PublicKey

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/Certificate.html
abstract class Certificate protected (certType: String) extends Serializable {

  override def equals(other: Any): Boolean = ???

  def getEncoded(): Array[Byte]

  def getPublicKey(): PublicKey

  final def getType: String = certType

  override def hashCode(): Int = ???

  override def toString: String = ???

  def verify(key: PublicKey): Unit

  def verify(key: PublicKey, sigProvider: String): Unit

  def verify(key: PublicKey, sigProvider: Provider): Unit

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

  protected class CertificateRep(repType: String, repData: Array[Byte])
      extends Serializable {

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

}
