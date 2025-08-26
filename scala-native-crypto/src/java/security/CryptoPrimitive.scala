package java.security

// https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/CryptoPrimitive.html
sealed abstract class CryptoPrimitive
object CryptoPrimitive {

  /** Symmetric primitive: block cipher */
  case object BLOCK_CIPHER extends CryptoPrimitive

  /** Asymmetric primitive: key agreement and key distribution */
  case object KEY_AGREEMENT extends CryptoPrimitive

  /** Asymmetric primitive: key encapsulation mechanism */
  case object KEY_ENCAPSULATION extends CryptoPrimitive

  /** Symmetric primitive: key wrap */
  case object KEY_WRAP extends CryptoPrimitive

  /** Symmetric primitive: message authentication code */
  case object MAC extends CryptoPrimitive

  /** Hash function */
  case object MESSAGE_DIGEST extends CryptoPrimitive

  /** Asymmetric primitive: public key encryption */
  case object PUBLIC_KEY_ENCRYPTION extends CryptoPrimitive

  /** Cryptographic random number generator */
  case object SECURE_RANDOM extends CryptoPrimitive

  /** Asymmetric primitive: signature scheme */
  case object SIGNATURE extends CryptoPrimitive

  /** Symmetric primitive: stream cipher */
  case object STREAM_CIPHER extends CryptoPrimitive

}
