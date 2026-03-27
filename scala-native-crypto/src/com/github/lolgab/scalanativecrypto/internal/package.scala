package com.github.lolgab.scalanativecrypto.internal

import java.security.NoSuchAlgorithmException
import scala.scalanative.unsafe._

import scala.scalanative.libc.stdio.FILE

@link("crypto")
@extern
object crypto {

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
  type X509_NAME_* = CVoidPtr
  type ASN1_INTEGER_* = CVoidPtr
  type ASN1_TIME_* = CVoidPtr

  def X509_new(): X509_* = extern
  def X509_free(x: X509_*): Unit = extern
  def X509_get0_serialNumber(x: X509_*): ASN1_INTEGER_* = extern
  def X509_get0_notBefore(x: X509_*): ASN1_TIME_* = extern
  def X509_get0_notAfter(x: X509_*): ASN1_TIME_* = extern
  def X509_get0_pubkey(x: X509_*): EVP_PKEY_* = extern
  def X509_get_subject_name(a: X509_*): X509_NAME_* = extern

  def i2d_X509_NAME_fp(fp: Ptr[FILE], a: X509_NAME_*): CInt = extern
}

object Constants {
  val EVP_MAX_MD_SIZE: Int = 64
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
