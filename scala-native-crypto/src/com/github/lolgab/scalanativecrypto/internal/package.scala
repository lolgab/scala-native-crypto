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

  // -- EVP Cipher API --

  type EVP_CIPHER_* = CVoidPtr
  type EVP_CIPHER_CTX_* = CVoidPtr

  def EVP_CIPHER_CTX_new(): EVP_CIPHER_CTX_* = extern
  def EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX_*): Unit = extern
  def EVP_CIPHER_CTX_reset(ctx: EVP_CIPHER_CTX_*): CInt = extern
  def EVP_CIPHER_CTX_ctrl(
      ctx: EVP_CIPHER_CTX_*,
      `type`: CInt,
      arg: CInt,
      ptr: CVoidPtr
  ): CInt = extern
  def EVP_CIPHER_CTX_block_size(ctx: EVP_CIPHER_CTX_*): CInt = extern

  def EVP_aes_128_gcm(): EVP_CIPHER_* = extern
  def EVP_aes_256_gcm(): EVP_CIPHER_* = extern
  def EVP_aes_128_cbc(): EVP_CIPHER_* = extern
  def EVP_aes_256_cbc(): EVP_CIPHER_* = extern

  def EVP_EncryptInit_ex(
      ctx: EVP_CIPHER_CTX_*,
      cipher: EVP_CIPHER_*,
      impl: CVoidPtr,
      key: Ptr[Byte],
      iv: Ptr[Byte]
  ): CInt = extern
  def EVP_EncryptUpdate(
      ctx: EVP_CIPHER_CTX_*,
      out: Ptr[Byte],
      outl: Ptr[CInt],
      in: Ptr[Byte],
      inl: CInt
  ): CInt = extern
  def EVP_EncryptFinal_ex(
      ctx: EVP_CIPHER_CTX_*,
      out: Ptr[Byte],
      outl: Ptr[CInt]
  ): CInt = extern

  def EVP_DecryptInit_ex(
      ctx: EVP_CIPHER_CTX_*,
      cipher: EVP_CIPHER_*,
      impl: CVoidPtr,
      key: Ptr[Byte],
      iv: Ptr[Byte]
  ): CInt = extern
  def EVP_DecryptUpdate(
      ctx: EVP_CIPHER_CTX_*,
      out: Ptr[Byte],
      outl: Ptr[CInt],
      in: Ptr[Byte],
      inl: CInt
  ): CInt = extern
  def EVP_DecryptFinal_ex(
      ctx: EVP_CIPHER_CTX_*,
      out: Ptr[Byte],
      outl: Ptr[CInt]
  ): CInt = extern
}

object Constants {
  val EVP_MAX_MD_SIZE: Int = 64

  // EVP_CIPHER_CTX_ctrl types
  val EVP_CTRL_AEAD_SET_IVLEN: Int = 0x9
  val EVP_CTRL_AEAD_GET_TAG: Int = 0x10
  val EVP_CTRL_AEAD_SET_TAG: Int = 0x11
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
