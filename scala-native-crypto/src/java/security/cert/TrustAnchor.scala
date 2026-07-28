package java.security.cert

import java.security.PublicKey
import javax.security.auth.x500.X500Principal

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/TrustAnchor.html
class TrustAnchor protected (
    trustedCert: X509Certificate,
    nameConstraints: Array[Byte]
) {

  def this(
      caPrincipal: X500Principal,
      pubKey: PublicKey,
      nameConstraints: Array[Byte]
  ) =
    this(???, nameConstraints)

  def this(caName: String, pubKey: PublicKey, nameConstraints: Array[Byte]) =
    this(???, nameConstraints)

  final def getTrustedCert(): X509Certificate = trustedCert

  final def getCA(): X500Principal = ???

  final def getCAName(): String = ???

  final def getCAPublicKey(): PublicKey = ???

  final def getNameConstraints(): Array[Byte] = nameConstraints

  override def toString(): String = ???

}
