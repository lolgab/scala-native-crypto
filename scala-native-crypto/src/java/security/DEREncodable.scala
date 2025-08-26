package java.security

// Can only be impled by
//
// - AsymmetricKey
// - KeyPair
// - PKCS8EncodedKeySpec
// - X509EncodedKeySpec
// - EncryptedPrivateKeyInfo
// - X509Certificate
// - X509CRL
// - PEMRecord
trait DEREncodable {}
