package com.github.lolgab.scalanativecrypto.internal

import scala.scalanative.unsafe._
import java.security.NoSuchAlgorithmException

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
}

object Constants {
  val EVP_MAX_MD_SIZE: Int = 64
}
object Utils {
  def getAlgorithmNameAndLength(algorithm: String, prefix: String) = {
    algorithm.toUpperCase().stripPrefix(prefix) match {
      case "MD5"                    => (c"MD5", 16)
      case "SHA-1" | "SHA" | "SHA1" => (c"SHA-1", 20)
      case "SHA-224" | "SHA224"     => (c"SHA-224", 28)
      case "SHA-256" | "SHA256"     => (c"SHA-256", 32)
      case "SHA-384" | "SHA384"     => (c"SHA-384", 48)
      case "SHA-512" | "SHA512"     => (c"SHA-512", 64)
      case _ =>
        throw new NoSuchAlgorithmException(
          s"$algorithm MessageDigest not available"
        )
    }
  }
}
