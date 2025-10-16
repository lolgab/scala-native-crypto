package java.security.cert

import java.util.{Set => JSet}

/// ## Refs
///
/// - https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/X509Extension.html
trait X509Extension {
  def getCriticalExtensionOIDs(): JSet[String]

  def getExtensionValue(oid: String): Array[Byte]

  def getNonCriticalExtensionOIDs(): JSet[String]

  def hasUnsupportedCriticalExtension(): Boolean
}
