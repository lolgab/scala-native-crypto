package java.security.cert

import java.math.BigInteger
import java.util.Date
import java.util.{List => JList}
import java.util.Collection

import java.security.DEREncodable
import javax.security.auth.x500.X500Principal

// ref: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/X509Certificate.html
abstract class X509Certificate(certType: String)
    extends Certificate(certType)
    with X509Extension
    with DEREncodable {
  def checkValidity(): Unit

  def checkValidity(date: Date): Unit

  def getBasicConstraints(): Int

  def getExtendedKeyUsage(): JList[String]

  def getIssuerAlternativeNames(): Collection[JList[?]]

  // @deprecated
  // def getIssuerDN(): Principal

  def getIssuerUniqueID(): Array[Boolean]

  def getIssuerX500Principal(): X500Principal

  def getKeyUsage(): Array[Boolean]

  def getNotAfter(): Date

  def getNotBefore(): Date

  def getSerialNumber(): BigInteger

  def getSigAlgName(): String

  def getSigAlgOID(): String

  def getSigAlgParams(): Array[Byte]

  def getSignature(): Array[Byte]

  def getSubjectAlternativeNames(): Collection[JList[?]]

  // @deprecated
  // def getSubjectDN(): Principal

  def getSubjectUniqueID(): Array[Boolean]

  def getSubjectX500Principal(): X500Principal

  def getTBSCertificate(): Array[Byte]

  def getVersion(): Int

  // declared in Certificate
  // def verify(key: PublicKey, sigProvider: Provider): Unit
}
