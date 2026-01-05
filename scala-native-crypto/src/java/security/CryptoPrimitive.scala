package java.security

import java.lang._Enum

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/CryptoPrimitive.html
 */
sealed class CryptoPrimitive private (name: String, ordinal: Int)
    extends _Enum[CryptoPrimitive](name, ordinal)
object CryptoPrimitive {

  final val BLOCK_CIPHER = new CryptoPrimitive("BLOCK_CIPHER", 0)
  final val KEY_AGREEMENT = new CryptoPrimitive("KEY_AGREEMENT", 1)
  final val KEY_ENCAPSULATION = new CryptoPrimitive("KEY_ENCAPSULATION", 2)
  final val KEY_WRAP = new CryptoPrimitive("KEY_WRAP", 3)
  final val MAC = new CryptoPrimitive("MAC", 4)
  final val MESSAGE_DIGEST = new CryptoPrimitive("MESSAGE_DIGEST", 5)
  final val PUBLIC_KEY_ENCRYPTION =
    new CryptoPrimitive("PUBLIC_KEY_ENCRYPTION", 6)
  final val SECURE_RANDOM = new CryptoPrimitive("SECURE_RANDOM", 7)
  final val SIGNATURE = new CryptoPrimitive("SIGNATURE", 8)
  final val STREAM_CIPHER = new CryptoPrimitive("STREAM_CIPHER", 9)

  val _values = Array(
    BLOCK_CIPHER,
    KEY_AGREEMENT,
    KEY_ENCAPSULATION,
    KEY_WRAP,
    MAC,
    MESSAGE_DIGEST,
    PUBLIC_KEY_ENCRYPTION,
    SECURE_RANDOM,
    SIGNATURE,
    STREAM_CIPHER
  )

  def values(): Array[CryptoPrimitive] = _values.clone()
  def valueOf(name: String): CryptoPrimitive = {
    _values
      .find(_.name() == name)
      .getOrElse({
        throw new IllegalArgumentException(
          "No enum const CryptoPrimitive." + name
        )
      })
  }
}
