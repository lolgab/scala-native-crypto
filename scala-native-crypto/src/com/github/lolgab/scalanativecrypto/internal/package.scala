package com.github.lolgab.scalanativecrypto.internal

import java.security.NoSuchAlgorithmException
import scala.scalanative.unsafe._

@link("crypto")
@extern
object crypto {
  type EVP_MD_* = CVoidPtr
  type EVP_MD_CTX_* = CVoidPtr

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

  // Function to get the SHA-256 algorithm
  def EVP_sha256(): EVP_MD_* = extern

  // --- EVP_PKEY for Ed25519 ---
  type EVP_PKEY_* = CVoidPtr
  type EVP_PKEY_CTX_* = CVoidPtr
  type ENGINE_* = CVoidPtr

  def EVP_PKEY_new(): EVP_PKEY_* = extern
  def EVP_PKEY_free(pkey: EVP_PKEY_*): Unit = extern

  def EVP_PKEY_CTX_new_id(id: CInt, e: ENGINE_*): EVP_PKEY_CTX_* = extern
  def EVP_PKEY_CTX_free(ctx: EVP_PKEY_CTX_*): Unit = extern
  def EVP_PKEY_keygen_init(ctx: EVP_PKEY_CTX_*): CInt = extern
  def EVP_PKEY_keygen(ctx: EVP_PKEY_CTX_*, ppkey: Ptr[EVP_PKEY_*]): CInt = extern

  // Signing/verification via DigestSign API (used for Ed25519)
  def EVP_DigestSignInit(ctx: EVP_MD_CTX_*, pctx: Ptr[EVP_PKEY_CTX_*], tpe: EVP_MD_*, e: ENGINE_*, pkey: EVP_PKEY_*): CInt = extern
  def EVP_DigestSign(ctx: EVP_MD_CTX_*, sig: Ptr[Byte], siglen: Ptr[CSize], tbs: Ptr[Byte], tbslen: CSize): CInt = extern
  def EVP_DigestVerifyInit(ctx: EVP_MD_CTX_*, pctx: Ptr[EVP_PKEY_CTX_*], tpe: EVP_MD_*, e: ENGINE_*, pkey: EVP_PKEY_*): CInt = extern
  def EVP_DigestVerify(ctx: EVP_MD_CTX_*, sig: Ptr[Byte], siglen: CSize, tbs: Ptr[Byte], tbslen: CSize): CInt = extern

  // Key import/export (raw format for Ed25519: 32 bytes pub, 64 bytes priv)
  def EVP_PKEY_new_raw_public_key(tpe: CInt, e: ENGINE_*, key: Ptr[Byte], keylen: CSize): EVP_PKEY_* = extern
  def EVP_PKEY_new_raw_private_key(tpe: CInt, e: ENGINE_*, key: Ptr[Byte], keylen: CSize): EVP_PKEY_* = extern
  def EVP_PKEY_get_raw_public_key(pkey: EVP_PKEY_*, pub: Ptr[Byte], len: Ptr[CSize]): CInt = extern
  def EVP_PKEY_get_raw_private_key(pkey: EVP_PKEY_*, priv: Ptr[Byte], len: Ptr[CSize]): CInt = extern
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
