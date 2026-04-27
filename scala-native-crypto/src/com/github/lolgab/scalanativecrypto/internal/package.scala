package com.github.lolgab.scalanativecrypto.internal

import java.security.NoSuchAlgorithmException
import scala.scalanative.unsafe._

import scala.scalanative.unsigned.UnsignedRichInt

@link("crypto")
@extern
object crypto {

  // Global
  type OSSL_LIB_CTX_* = CVoidPtr
  def OSSL_LIB_CTX_new(): OSSL_LIB_CTX_* = extern
  def OSSL_LIB_CTX_free(ctx: OSSL_LIB_CTX_*): Unit = extern
  def OSSL_LIB_CTX_get0_global_default(): OSSL_LIB_CTX_* = extern

  // BIO operations
  type BIO_* = CVoidPtr
  type BIO_METHOD_* = CVoidPtr
  type BIO_CTRL_* = CInt

  def BIO_s_mem(): BIO_METHOD_* = extern
  def BIO_s_secmem(): BIO_METHOD_* = extern
  def BIO_new(typ: BIO_METHOD_*): BIO_* = extern
  def BIO_new_mem_buf(buf: Ptr[Byte], len: CInt): BIO_* = extern
  def BIO_free(a: BIO_METHOD_*): CInt = extern
  def BIO_gets(b: BIO_*, buf: Ptr[CChar], size: CInt): CInt = extern

  // def BIO_get_mem_data(b: BIO_*, pp: Ptr[CString]): CLong = extern

  // EVP related types and functions

  type EVP_MD_* = CVoidPtr
  type EVP_MD_CTX_* = CVoidPtr
  type EVP_PKEY_* = CVoidPtr

  def RAND_bytes(buf: Ptr[Byte], num: CInt): CInt = extern

  def EVP_get_digestbyname(name: CString): EVP_MD_* = extern

  def EVP_MD_CTX_new(): EVP_MD_CTX_* = extern
  def EVP_MD_CTX_free(ctx: EVP_MD_CTX_*): Unit = extern
  def EVP_MD_CTX_reset(ctx: EVP_MD_CTX_*): Unit = extern

  def EVP_DigestInit(ctx: EVP_MD_CTX_*, tpe: EVP_MD_*): CInt = extern
  def EVP_DigestUpdate(ctx: EVP_MD_CTX_*, d: Ptr[Byte], cnt: CSize): CInt =
    extern
  def EVP_DigestFinal(ctx: EVP_MD_CTX_*, md: Ptr[Byte], s: Ptr[Int]): CInt =
    extern

  def EVP_sha256(): EVP_MD_* = extern // Function to get the SHA-256 algorithm

  // HMAC related types and functions
  type HMAC_CTX_* = CVoidPtr

  def HMAC_CTX_new(): HMAC_CTX_* = extern
  def HMAC_CTX_reset(ctx: HMAC_CTX_*): Unit = extern
  def HMAC_CTX_free(ctx: HMAC_CTX_*): Unit = extern
  def HMAC_Init_ex(
      ctx: HMAC_CTX_*,
      key: CVoidPtr,
      key_len: CInt,
      md: EVP_MD_*,
      impl: CVoidPtr
  ): CInt = extern
  def HMAC_Update(ctx: HMAC_CTX_*, data: Ptr[Byte], len: Int): CInt =
    extern
  def HMAC_Final(ctx: HMAC_CTX_*, md: Ptr[Byte], len: Ptr[Int]): CInt =
    extern

  // X509 related types and functions
  type X509_* = CVoidPtr
  type stack_st_X509 = CVoidPtr

  type ASN1_INTEGER_* = CVoidPtr
  type ASN1_TIME_* = CVoidPtr

  def X509_new(): X509_* = extern
  def X509_free(x: X509_*): Unit = extern
  def X509_get0_serialNumber(x: X509_*): ASN1_INTEGER_* = extern
  def X509_get0_notBefore(x: X509_*): ASN1_TIME_* = extern
  def X509_get0_notAfter(x: X509_*): ASN1_TIME_* = extern
  def X509_get0_pubkey(x: X509_*): EVP_PKEY_* = extern
  def X509_get_subject_name(a: X509_*): X509_NAME_* = extern
  def X509_check_ca(cert: X509_*): CInt = extern

  def PEM_read_bio_X509(
      bp: BIO_*,
      x: Ptr[X509_*],
      cb: Ptr[pem_password_cb],
      u: CVoidPtr
  ): X509_* =
    extern

  // X509_NAME and ASN1_STRING related types and functions
  type X509_NAME_* = CVoidPtr

  def X509_NAME_print_ex(
      out: BIO_*,
      nm: X509_NAME_*,
      indent: CInt,
      flags: CUnsignedLong
  ): CInt =
    extern

  // PKCS7 related types and functions
  type PKCS7_* = CVoidPtr

  def PEM_read_bio_PKCS7(
      bp: BIO_*,
      x: Ptr[PKCS7_*],
      cb: Ptr[pem_password_cb],
      u: CVoidPtr
  ): PKCS7_* =
    extern

  // PKCS12 related types and functions
  type PKCS12_* = CVoidPtr

  def d2i_PKCS12_bio(bp: BIO_*, p12: Ptr[PKCS12_*]): PKCS12_* = extern

  def PKCS12_verify_mac(
      p12: PKCS12_*,
      pass: CString,
      passlen: CInt
  ): CInt = extern
  def PKCS12_parse(
      p12: PKCS12_*,
      pass: CString,
      pkey: Ptr[EVP_PKEY_*],
      cert: Ptr[X509_*],
      ca: Ptr[Ptr[stack_st_X509]]
  ): CInt = extern

  // Other types and functions
  type pem_password_cb = CFuncPtr4[CString, CInt, CInt, Ptr[Byte], CInt]

}

object Constants {
  val EVP_MAX_MD_SIZE: Int = 64

  /**
   * Parameters used by `ASN1_STRING_print_ex()`
   *
   * Refer to
   * https://github.com/openssl/openssl/blob/febac4fbf34d6506154795b91a9610da905f1fcb/include/openssl/asn1.h.in#L359-L391
   */

  val ASN1_STRFLGS_ESC_2253: CUnsignedLong = 1.toUSize
  val ASN1_STRFLGS_ESC_CTRL: CUnsignedLong = 2.toUSize
  val ASN1_STRFLGS_ESC_MSB: CUnsignedLong = 4.toUSize
  val ASN1_STRFLGS_UTF8_CONVERT: CUnsignedLong = 0x10.toUSize
  val ASN1_STRFLGS_DUMP_UNKNOWN: CUnsignedLong = 0x100.toUSize
  val ASN1_STRFLGS_DUMP_DER: CUnsignedLong = 0x200.toUSize

  val ASN1_STRFLGS_RFC2253: CUnsignedLong =
    (ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB | ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_DUMP_UNKNOWN | ASN1_STRFLGS_DUMP_DER)

  /**
   * Flags specific to `X509_NAME_print_ex()`
   *
   * Refer to
   * https://github.com/openssl/openssl/blob/febac4fbf34d6506154795b91a9610da905f1fcb/include/openssl/x509.h.in#L153-L198
   */

  val XN_FLAG_SEP_COMMA_PLUS: CUnsignedLong = (1 << 16).toUSize
  val XN_FLAG_DN_REV: CUnsignedLong = (1 << 20).toUSize
  val XN_FLAG_FN_SN: CUnsignedLong = 0.toUSize
  val XN_FLAG_DUMP_UNKNOWN_FIELDS = (1 << 24).toUSize

  val XN_FLAG_RFC2253: CUnsignedLong =
    ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_DN_REV | XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS
}

object Utils {
  def getAlgorithmNameAndLength(
      algorithm: String,
      prefix: String
  ): (CString, CInt) = {
    algorithm.toUpperCase().stripPrefix(prefix) match {
      case "MD5"                    => (c"MD5", 16)
      case "SHA-1" | "SHA" | "SHA1" => (c"SHA1", 20)
      case "SHA-224" | "SHA224"     => (c"SHA224", 28)
      case "SHA-256" | "SHA256"     => (c"SHA256", 32)
      case "SHA-384" | "SHA384"     => (c"SHA384", 48)
      case "SHA-512" | "SHA512"     => (c"SHA512", 64)
      case "SHA3-224"               => (c"SHA3-224", 28)
      case "SHA3-256"               => (c"SHA3-256", 32)
      case "SHA3-384"               => (c"SHA3-384", 48)
      case "SHA3-512"               => (c"SHA3-512", 64)
      case _ =>
        throw new NoSuchAlgorithmException(
          s"$algorithm MessageDigest not available"
        )
    }
  }
}
