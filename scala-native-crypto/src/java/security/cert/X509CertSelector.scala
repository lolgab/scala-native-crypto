package java.security.cert

import java.io.IOException
import java.math.BigInteger
import java.security.PublicKey
import java.util.{Collection, Date, List => JList, Set => JSet}
import javax.security.auth.x500.X500Principal

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/X509CertSelector.html
 */
class X509CertSelector() extends CertSelector {

  def setCertificate(cert: X509Certificate): Unit = ???

  def getCertificate(): X509Certificate = ???

  def setSerialNumber(serial: BigInteger): Unit = ???

  def getSerialNumber(): BigInteger = ???

  def setIssuer(issuer: X500Principal): Unit = ???

  @deprecated("Use setIssuer(X500Principal) or setIssuer(byte[]) instead", "16")
  def setIssuer(issuerDN: String): Unit = ???

  def setIssuer(issuerDN: Array[Byte]): Unit = ???

  def getIssuer(): X500Principal = ???

  @deprecated("Use getIssuer() or getIssuerAsBytes() instead", "16")
  def getIssuerAsString(): String = ???

  def getIssuerAsBytes(): Array[Byte] = ???

  def setSubject(subject: X500Principal): Unit = ???

  @deprecated(
    "Use setSubject(X500Principal) or setSubject(byte[]) instead",
    "16"
  )
  def setSubject(subjectDN: String): Unit = ???

  def setSubject(subjectDN: Array[Byte]): Unit = ???

  def getSubject(): X500Principal = ???

  @deprecated("Use getSubject() or getSubjectAsBytes() instead", "16")
  def getSubjectAsString(): String = ???

  def getSubjectAsBytes(): Array[Byte] = ???

  def setSubjectKeyIdentifier(subjectKeyID: Array[Byte]): Unit = ???

  def getSubjectKeyIdentifier(): Array[Byte] = ???

  def setAuthorityKeyIdentifier(authorityKeyID: Array[Byte]): Unit = ???

  def getAuthorityKeyIdentifier(): Array[Byte] = ???

  def setCertificateValid(certValid: Date): Unit = ???

  def getCertificateValid(): Date = ???

  def setPrivateKeyValid(privateKeyValid: Date): Unit = ???

  def getPrivateKeyValid(): Date = ???

  def setSubjectPublicKeyAlgID(oid: String): Unit = ???

  def getSubjectPublicKeyAlgID(): String = ???

  def setSubjectPublicKey(key: PublicKey): Unit = ???

  def setSubjectPublicKey(key: Array[Byte]): Unit = ???

  def getSubjectPublicKey(): PublicKey = ???

  def setKeyUsage(keyUsage: Array[Boolean]): Unit = ???

  def getKeyUsage(): Array[Boolean] = ???

  def setExtendedKeyUsage(keyPurposeSet: JSet[String]): Unit = ???

  def getExtendedKeyUsage(): JSet[String] = ???

  def setMatchAllSubjectAltNames(matchAllNames: Boolean): Unit = ???

  def getMatchAllSubjectAltNames(): Boolean = ???

  def setSubjectAlternativeNames(names: Collection[JList[?]]): Unit = ???

  def addSubjectAlternativeName(`type`: Int, name: String): Unit = ???

  def addSubjectAlternativeName(`type`: Int, name: Array[Byte]): Unit = ???

  def getSubjectAlternativeNames(): Collection[JList[?]] = ???

  def setNameConstraints(bytes: Array[Byte]): Unit = ???

  def getNameConstraints(): Array[Byte] = ???

  def setBasicConstraints(minMaxPathLen: Int): Unit = ???

  def getBasicConstraints(): Int = ???

  def setPolicy(certPolicySet: JSet[String]): Unit = ???

  def getPolicy(): JSet[String] = ???

  def setPathToNames(names: Collection[JList[?]]): Unit = ???

  def addPathToName(`type`: Int, name: String): Unit = ???

  def addPathToName(`type`: Int, name: Array[Byte]): Unit = ???

  def getPathToNames(): Collection[JList[?]] = ???

  def `match`(cert: Certificate): Boolean = ???

  override def clone(): Object = ???

  override def toString(): String = ???

}
