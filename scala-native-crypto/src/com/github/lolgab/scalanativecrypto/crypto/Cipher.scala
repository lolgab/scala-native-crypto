package com.github.lolgab.scalanativecrypto.crypto

import com.github.lolgab.scalanativecrypto.internal.Constants._
import com.github.lolgab.scalanativecrypto.internal._

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer
import java.security.{InvalidAlgorithmParameterException, InvalidKeyException, Key, Provider}
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.{AEADBadTagException, BadPaddingException, Cipher}
import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec, SecretKeySpec}
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.runtime.ByteArray
import scala.scalanative.unsafe._

/**
 * OpenSSL-backed Cipher implementation supporting AES/GCM/NoPadding and
 * AES/CBC/PKCS5Padding.
 */
final class OpenSslCipher protected[scalanativecrypto] (
    provider: Provider,
    transformation: String,
    mode: String,
    padding: String
) extends Cipher(null, provider, transformation) {

  private val ctx: crypto.EVP_CIPHER_CTX_* = crypto.EVP_CIPHER_CTX_new()
  if (ctx == null) {
    throw new RuntimeException("Failed to create cipher context")
  }

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_EVP_CIPHER_CTX(this, ctx)
  } else {
    System.err.println(
      "[javax.crypto.Cipher] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  private var opmode: Int = -1
  private var isGcm: Boolean = mode == "GCM"
  private var gcmTagLen: Int = 16 // default 128-bit tag
  private var iv: Array[Byte] = _
  private var initialized: Boolean = false

  // Accumulated data for GCM (we need to buffer for tag handling)
  private var accumulated: Array[Byte] = Array.empty

  override def getBlockSize(): Int =
    if (isGcm) 1 // GCM is a stream cipher mode
    else 16 // AES block size for CBC

  override def getIV(): Array[Byte] =
    if (iv == null) null else iv.clone()

  override def init(opmode: Int, key: Key): Unit =
    init(opmode, key, null: AlgorithmParameterSpec)

  override def init(opmode: Int, key: Key, params: AlgorithmParameterSpec): Unit = {
    require(
      opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.DECRYPT_MODE,
      s"Unsupported opmode: $opmode"
    )
    this.opmode = opmode
    this.accumulated = Array.empty

    val keySpec = key match {
      case k: SecretKeySpec => k
      case _ => throw new InvalidKeyException("Only SecretKeySpec is supported")
    }
    val keyBytes = keySpec.getEncoded()

    // Determine the EVP_CIPHER based on key size and mode
    val evpCipher = (keyBytes.length, mode) match {
      case (16, "GCM") => crypto.EVP_aes_128_gcm()
      case (32, "GCM") => crypto.EVP_aes_256_gcm()
      case (16, "CBC") => crypto.EVP_aes_128_cbc()
      case (32, "CBC") => crypto.EVP_aes_256_cbc()
      case (len, _) =>
        throw new InvalidKeyException(
          s"Invalid AES key length: ${len * 8} bits"
        )
    }

    // Extract IV/nonce from params
    val ivBytes: Array[Byte] = params match {
      case gcm: GCMParameterSpec =>
        if (!isGcm)
          throw new InvalidAlgorithmParameterException(
            "GCMParameterSpec used with non-GCM cipher"
          )
        gcmTagLen = gcm.getTLen() / 8
        gcm.getIV()
      case ivp: IvParameterSpec =>
        ivp.getIV()
      case null =>
        throw new InvalidAlgorithmParameterException(
          "Parameters required for AES cipher"
        )
      case _ =>
        throw new InvalidAlgorithmParameterException(
          s"Unsupported parameter type: ${params.getClass.getName}"
        )
    }
    this.iv = ivBytes

    // Reset context
    crypto.EVP_CIPHER_CTX_reset(ctx)

    if (isGcm) {
      // For GCM: init cipher, set IV length, then set key+IV
      val initFn =
        if (opmode == Cipher.ENCRYPT_MODE) crypto.EVP_EncryptInit_ex _
        else crypto.EVP_DecryptInit_ex _

      if (initFn(ctx, evpCipher, null, null, null) != 1)
        throw new RuntimeException("Failed to initialize cipher")

      if (
        crypto.EVP_CIPHER_CTX_ctrl(
          ctx,
          EVP_CTRL_AEAD_SET_IVLEN,
          ivBytes.length,
          null
        ) != 1
      )
        throw new RuntimeException("Failed to set IV length")

      if (initFn(ctx, null, null, keyBytes.at(0), ivBytes.at(0)) != 1)
        throw new RuntimeException("Failed to set key and IV")
    } else {
      // For CBC: straightforward init
      if (ivBytes.length != 16)
        throw new InvalidAlgorithmParameterException(
          s"Wrong IV length: must be 16 bytes, got ${ivBytes.length}"
        )

      val initFn =
        if (opmode == Cipher.ENCRYPT_MODE) crypto.EVP_EncryptInit_ex _
        else crypto.EVP_DecryptInit_ex _

      if (initFn(ctx, evpCipher, null, keyBytes.at(0), ivBytes.at(0)) != 1)
        throw new RuntimeException("Failed to initialize cipher")
    }

    initialized = true
  }

  override def updateAAD(src: Array[Byte]): Unit =
    updateAAD(src, 0, src.length)

  override def updateAAD(src: Array[Byte], offset: Int, len: Int): Unit = {
    require(initialized, "Cipher not initialized")
    require(isGcm, "AAD is only supported for GCM mode")

    if (len > 0) {
      val outl = stackalloc[CInt]()
      val dataPtr = src.asInstanceOf[ByteArray].at(offset)

      val rc =
        if (opmode == Cipher.ENCRYPT_MODE)
          crypto.EVP_EncryptUpdate(ctx, null, outl, dataPtr, len)
        else
          crypto.EVP_DecryptUpdate(ctx, null, outl, dataPtr, len)

      if (rc != 1)
        throw new RuntimeException("Failed to process AAD")
    }
  }

  override def update(input: Array[Byte]): Array[Byte] =
    update(input, 0, input.length)

  override def update(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int
  ): Array[Byte] = {
    require(initialized, "Cipher not initialized")

    if (isGcm) {
      // For GCM, accumulate data and process in doFinal
      // This simplifies tag handling
      val chunk = new Array[Byte](inputLen)
      System.arraycopy(input, inputOffset, chunk, 0, inputLen)
      accumulated = accumulated ++ chunk
      Array.empty[Byte]
    } else {
      // For CBC, process immediately
      val maxOut = inputLen + 16 // at most one extra block
      val outBuf = new Array[Byte](maxOut)
      val outl = stackalloc[CInt]()
      val inPtr = input.asInstanceOf[ByteArray].at(inputOffset)

      val rc =
        if (opmode == Cipher.ENCRYPT_MODE)
          crypto.EVP_EncryptUpdate(
            ctx,
            outBuf.asInstanceOf[ByteArray].at(0),
            outl,
            inPtr,
            inputLen
          )
        else
          crypto.EVP_DecryptUpdate(
            ctx,
            outBuf.asInstanceOf[ByteArray].at(0),
            outl,
            inPtr,
            inputLen
          )

      if (rc != 1)
        throw new RuntimeException("Failed to update cipher")

      val written = !outl
      val result = new Array[Byte](written)
      System.arraycopy(outBuf, 0, result, 0, written)
      result
    }
  }

  override def doFinal(): Array[Byte] = doFinal(Array.empty[Byte], 0, 0)

  override def doFinal(input: Array[Byte]): Array[Byte] =
    doFinal(input, 0, input.length)

  override def doFinal(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int
  ): Array[Byte] = {
    require(initialized, "Cipher not initialized")

    if (isGcm) doFinalGcm(input, inputOffset, inputLen)
    else doFinalCbc(input, inputOffset, inputLen)
  }

  private def doFinalGcm(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int
  ): Array[Byte] = {
    // Combine accumulated data with any final input
    val allInput =
      if (inputLen > 0) {
        val chunk = new Array[Byte](inputLen)
        System.arraycopy(input, inputOffset, chunk, 0, inputLen)
        accumulated ++ chunk
      } else accumulated

    accumulated = Array.empty

    if (opmode == Cipher.ENCRYPT_MODE) {
      // Encrypt all data
      val maxOut = allInput.length + 16 // room for potential extra
      val outBuf = new Array[Byte](maxOut)
      val outl = stackalloc[CInt]()
      var totalOut = 0

      if (allInput.nonEmpty) {
        if (
          crypto.EVP_EncryptUpdate(
            ctx,
            outBuf.asInstanceOf[ByteArray].at(0),
            outl,
            allInput.asInstanceOf[ByteArray].at(0),
            allInput.length
          ) != 1
        )
          throw new RuntimeException("Failed to encrypt data")
        totalOut += !outl
      }

      // Finalize
      if (
        crypto.EVP_EncryptFinal_ex(
          ctx,
          outBuf.asInstanceOf[ByteArray].at(totalOut),
          outl
        ) != 1
      )
        throw new RuntimeException("Failed to finalize encryption")
      totalOut += !outl

      // Get the auth tag
      val tag = new Array[Byte](gcmTagLen)
      if (
        crypto.EVP_CIPHER_CTX_ctrl(
          ctx,
          EVP_CTRL_AEAD_GET_TAG,
          gcmTagLen,
          tag.asInstanceOf[ByteArray].at(0)
        ) != 1
      )
        throw new RuntimeException("Failed to get GCM auth tag")

      // Return ciphertext || tag
      val result = new Array[Byte](totalOut + gcmTagLen)
      System.arraycopy(outBuf, 0, result, 0, totalOut)
      System.arraycopy(tag, 0, result, totalOut, gcmTagLen)
      result

    } else {
      // Decrypt: input is ciphertext || tag
      if (allInput.length < gcmTagLen)
        throw new AEADBadTagException("Input too short for GCM tag")

      val ciphertextLen = allInput.length - gcmTagLen
      val tag = new Array[Byte](gcmTagLen)
      System.arraycopy(allInput, ciphertextLen, tag, 0, gcmTagLen)

      // Set the expected tag before decrypting
      if (
        crypto.EVP_CIPHER_CTX_ctrl(
          ctx,
          EVP_CTRL_AEAD_SET_TAG,
          gcmTagLen,
          tag.asInstanceOf[ByteArray].at(0)
        ) != 1
      )
        throw new RuntimeException("Failed to set GCM auth tag")

      val outBuf = new Array[Byte](ciphertextLen + 16)
      val outl = stackalloc[CInt]()
      var totalOut = 0

      if (ciphertextLen > 0) {
        if (
          crypto.EVP_DecryptUpdate(
            ctx,
            outBuf.asInstanceOf[ByteArray].at(0),
            outl,
            allInput.asInstanceOf[ByteArray].at(0),
            ciphertextLen
          ) != 1
        )
          throw new RuntimeException("Failed to decrypt data")
        totalOut += !outl
      }

      // Finalize — returns 0 if auth tag doesn't match
      if (
        crypto.EVP_DecryptFinal_ex(
          ctx,
          outBuf.asInstanceOf[ByteArray].at(totalOut),
          outl
        ) != 1
      )
        throw new AEADBadTagException("GCM authentication failed")
      totalOut += !outl

      val result = new Array[Byte](totalOut)
      System.arraycopy(outBuf, 0, result, 0, totalOut)
      result
    }
  }

  private def doFinalCbc(
      input: Array[Byte],
      inputOffset: Int,
      inputLen: Int
  ): Array[Byte] = {
    val outl = stackalloc[CInt]()
    // Max output: inputLen + block size for update + block size for final
    val maxOut = inputLen + 32
    val outBuf = new Array[Byte](maxOut)
    var totalOut = 0

    // Process remaining input
    if (inputLen > 0) {
      val inPtr = input.asInstanceOf[ByteArray].at(inputOffset)

      val rc =
        if (opmode == Cipher.ENCRYPT_MODE)
          crypto.EVP_EncryptUpdate(
            ctx,
            outBuf.asInstanceOf[ByteArray].at(0),
            outl,
            inPtr,
            inputLen
          )
        else
          crypto.EVP_DecryptUpdate(
            ctx,
            outBuf.asInstanceOf[ByteArray].at(0),
            outl,
            inPtr,
            inputLen
          )

      if (rc != 1)
        throw new RuntimeException("Failed to update cipher")
      totalOut += !outl
    }

    // Finalize
    val rc =
      if (opmode == Cipher.ENCRYPT_MODE)
        crypto.EVP_EncryptFinal_ex(
          ctx,
          outBuf.asInstanceOf[ByteArray].at(totalOut),
          outl
        )
      else
        crypto.EVP_DecryptFinal_ex(
          ctx,
          outBuf.asInstanceOf[ByteArray].at(totalOut),
          outl
        )

    if (rc != 1)
      throw new BadPaddingException("Decryption failed (bad padding)")
    totalOut += !outl

    val result = new Array[Byte](totalOut)
    System.arraycopy(outBuf, 0, result, 0, totalOut)
    result
  }
}
