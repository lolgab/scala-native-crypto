package java.security.cert

import java.util.{Set => JSet}

trait X509Extension {
  def hasUnsupportedCriticalExtension(): Boolean

  def getCriticalExtensionOIDs(): JSet[String]

  def getNonCriticalExtensionOIDs(): JSet[String]

  def getExtensionValue(oid: String): Array[Byte]
}
