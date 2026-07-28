package java.security

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/KeyPair.html
final class KeyPair(
    publicKey: PublicKey,
    privateKey: PrivateKey
) extends Serializable {
  def getPrivate(): PrivateKey = privateKey
  def getPublic(): PublicKey = publicKey
}
