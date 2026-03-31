package scalanativecrypto

import utest._

import java.security.SecureRandom
import java.util.Arrays
import javax.crypto._
import javax.crypto.spec._

object CipherSuite extends TestSuite {

  private def randomBytes(n: Int): Array[Byte] = {
    val bytes = new Array[Byte](n)
    new SecureRandom().nextBytes(bytes)
    bytes
  }

  private def hexEncode(bytes: Array[Byte]): String =
    bytes.map(b => f"${b & 0xff}%02x").mkString

  val tests = Tests {

    // -- AES/GCM/NoPadding --

    test("AES-256-GCM round-trip") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "Hello, AES-GCM!".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-128-GCM round-trip") {
      val key = randomBytes(16)
      val nonce = randomBytes(12)
      val plaintext = "AES-128-GCM test".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-GCM empty plaintext") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ciphertext = cipher.doFinal(Array.empty[Byte])

      // Should be just the 16-byte tag
      assert(ciphertext.length == 16)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(decrypted.length == 0)
    }

    test("AES-GCM large plaintext") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = randomBytes(10000)

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ciphertext = cipher.doFinal(plaintext)

      assert(ciphertext.length == plaintext.length + 16)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-GCM with AAD") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "secret data".getBytes("UTF-8")
      val aad = "authenticated metadata".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      cipher.updateAAD(aad)
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      decipher.updateAAD(aad)
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-GCM deterministic with same key and nonce") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "test".getBytes("UTF-8")

      val cipher1 = Cipher.getInstance("AES/GCM/NoPadding")
      cipher1.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ct1 = cipher1.doFinal(plaintext)

      val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
      cipher2.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ct2 = cipher2.doFinal(plaintext)

      assert(Arrays.equals(ct1, ct2))
    }

    test("AES-GCM wrong key fails") {
      val key = randomBytes(32)
      val wrongKey = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "secret".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(wrongKey, "AES"),
        new GCMParameterSpec(128, nonce)
      )

      assertThrows[AEADBadTagException] {
        decipher.doFinal(ciphertext)
      }
    }

    test("AES-GCM tampered ciphertext fails") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "secret".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val ciphertext = cipher.doFinal(plaintext)

      // Tamper with the last byte (tag)
      ciphertext(ciphertext.length - 1) =
        (ciphertext(ciphertext.length - 1) ^ 0xff).toByte

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )

      assertThrows[AEADBadTagException] {
        decipher.doFinal(ciphertext)
      }
    }

    test("AES-GCM wrong AAD fails") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "secret".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      cipher.updateAAD("correct".getBytes("UTF-8"))
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      decipher.updateAAD("wrong".getBytes("UTF-8"))

      assertThrows[AEADBadTagException] {
        decipher.doFinal(ciphertext)
      }
    }

    // -- AES/CBC/PKCS5Padding --

    test("AES-256-CBC round-trip") {
      val key = randomBytes(32)
      val iv = randomBytes(16)
      val plaintext = "Hello, AES-CBC!".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-128-CBC round-trip") {
      val key = randomBytes(16)
      val iv = randomBytes(16)
      val plaintext = "AES-128-CBC test".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-CBC empty plaintext") {
      val key = randomBytes(32)
      val iv = randomBytes(16)

      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ciphertext = cipher.doFinal(Array.empty[Byte])

      // PKCS7 padding adds a full block for empty input
      assert(ciphertext.length == 16)

      val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(decrypted.length == 0)
    }

    test("AES-CBC block-aligned plaintext") {
      val key = randomBytes(32)
      val iv = randomBytes(16)
      val plaintext = new Array[Byte](48) // 3 blocks
      Arrays.fill(plaintext, 0x42.toByte)

      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ciphertext = cipher.doFinal(plaintext)

      // Block-aligned + PKCS7 adds one full padding block
      assert(ciphertext.length == 64)

      val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-CBC non-block-aligned plaintext") {
      val key = randomBytes(32)
      val iv = randomBytes(16)
      val plaintext = new Array[Byte](37)
      Arrays.fill(plaintext, 0xcd.toByte)

      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val decrypted = decipher.doFinal(ciphertext)

      assert(Arrays.equals(decrypted, plaintext))
    }

    test("AES-CBC deterministic with same key and IV") {
      val key = randomBytes(32)
      val iv = randomBytes(16)
      val plaintext = "test".getBytes("UTF-8")

      val cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher1.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ct1 = cipher1.doFinal(plaintext)

      val cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher2.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ct2 = cipher2.doFinal(plaintext)

      assert(Arrays.equals(ct1, ct2))
    }

    test("AES-CBC wrong key fails") {
      val key = randomBytes(32)
      val wrongKey = randomBytes(32)
      val iv = randomBytes(16)
      val plaintext = "secret".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv)
      )
      val ciphertext = cipher.doFinal(plaintext)

      val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(wrongKey, "AES"),
        new IvParameterSpec(iv)
      )

      assertThrows[BadPaddingException] {
        decipher.doFinal(ciphertext)
      }
    }

    // -- GCM with update() --

    test("AES-GCM using update then doFinal") {
      val key = randomBytes(32)
      val nonce = randomBytes(12)
      val plaintext = "Hello, World! This is a longer message.".getBytes("UTF-8")

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val updateOut = cipher.update(plaintext)
      val finalOut = cipher.doFinal()

      // Combine update + final output
      val ciphertext = updateOut ++ finalOut

      assert(ciphertext.length == plaintext.length + 16)

      val decipher = Cipher.getInstance("AES/GCM/NoPadding")
      decipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce)
      )
      val decUpdateOut = decipher.update(ciphertext)
      val decFinalOut = decipher.doFinal()

      val decrypted = decUpdateOut ++ decFinalOut

      assert(Arrays.equals(decrypted, plaintext))
    }

    // -- Spec classes --

    test("GCMParameterSpec stores IV correctly") {
      val iv = Array[Byte](1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
      val spec = new GCMParameterSpec(128, iv)
      assert(spec.getTLen() == 128)
      assert(Arrays.equals(spec.getIV(), iv))

      // Modifying original should not affect spec
      iv(0) = 0
      assert(spec.getIV()(0) == 1)
    }

    test("IvParameterSpec stores IV correctly") {
      val iv =
        Array[Byte](1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
      val spec = new IvParameterSpec(iv)
      assert(Arrays.equals(spec.getIV(), iv))

      // Modifying original should not affect spec
      iv(0) = 0
      assert(spec.getIV()(0) == 1)
    }

    test("GCMParameterSpec rejects null") {
      assertThrows[IllegalArgumentException] {
        new GCMParameterSpec(128, null)
      }
    }

    test("IvParameterSpec rejects null") {
      assertThrows[Exception] {
        new IvParameterSpec(null)
      }
    }
  }
}
