package java.security.cert

import java.lang._Enum

sealed class CRLReason private (name: String, ordinal: Int)
    extends _Enum[CRLReason](name, ordinal)

// Refs:
// 1. https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/cert/CRLReason.html
object CRLReason {

  final val UNSPECIFIED = new CRLReason("UNSPECIFIED", 0)
  final val KEY_COMPROMISE = new CRLReason("KEY_COMPROMISE", 1)
  final val CA_COMPROMISE = new CRLReason("CA_COMPROMISE", 2)
  final val AFFILIATION_CHANGED = new CRLReason("AFFILIATION_CHANGED", 3)
  final val SUPERSEDED = new CRLReason("SUPERSEDED", 4)
  final val CESSATION_OF_OPERATION =
    new CRLReason("CESSATION_OF_OPERATION", 5)
  final val CERTIFICATE_HOLD =
    new CRLReason("CERTIFICATE_HOLD", 6)
  final val UNUSED = new CRLReason("UNUSED", 7)
  final val REMOVE_FROM_CRL = new CRLReason("REMOVE_FROM_CRL", 8)
  final val PRIVILEGE_WITHDRAWN = new CRLReason("PRIVILEGE_WITHDRAWN", 9)
  final val AA_COMPROMISE = new CRLReason("AA_COMPROMISE", 10)

  val _values = Array(
    UNSPECIFIED,
    KEY_COMPROMISE,
    CA_COMPROMISE,
    AFFILIATION_CHANGED,
    SUPERSEDED,
    CESSATION_OF_OPERATION,
    CERTIFICATE_HOLD,
    UNUSED,
    REMOVE_FROM_CRL,
    PRIVILEGE_WITHDRAWN,
    AA_COMPROMISE
  )

  def values(): Array[CRLReason] = _values.clone()

  def valueOf(name: String): CRLReason = {
    _values
      .find(_.name() == name)
      .getOrElse({
        throw new IllegalArgumentException(
          "No enum const CRLReason." + name
        )
      })
  }
}
