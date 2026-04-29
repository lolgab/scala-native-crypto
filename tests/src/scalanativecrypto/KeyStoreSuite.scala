package scalanativecrypto

import utest.{TestSuite, Tests, assert, assertThrows, test}

import java.io.{ByteArrayInputStream, FileInputStream, IOException}
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.{
  PrivateKey,
  Provider,
  PublicKey,
  Security,
  UnrecoverableKeyException
}
import java.security.cert.{Certificate, X509Certificate}
import java.util.{HashSet, Collections}
import java.util.{List => JList}

class KeyStoreSuite extends TestSuite {

  private val testDataDir = sys.env("MILL_TEST_RESOURCE_DIR") + "/test-data"

  private def withFileInputStream[A](
      path: String
  )(func: FileInputStream => A): A = {
    val stream = new FileInputStream(path)
    try func(stream)
    finally stream.close()
  }

  private def loadPKCS12(path: String, password: Array[Char]): KeyStore = {
    val keyStore = KeyStore.getInstance("PKCS12")
    withFileInputStream(path) { stream => keyStore.load(stream, password) }
    assert(keyStore.getType() == "PKCS12")
    keyStore
  }

  val tests = Tests {

    test("KeyStore.getDefaultType returns pkcs12") {
      assert(KeyStore.getDefaultType() == "pkcs12")
    }

    test("KeyStore.getInstance should throw for invalid arguments") {
      assertThrows[NullPointerException] {
        KeyStore.getInstance(null.asInstanceOf[String])
      }
      assertThrows[KeyStoreException] {
        KeyStore.getInstance("")
      }
      assertThrows[IllegalArgumentException] {
        KeyStore.getInstance("PKCS12", null.asInstanceOf[Provider])
      }
      assertThrows[IllegalArgumentException] {
        KeyStore.getInstance("", null.asInstanceOf[Provider])
      }
    }

    test("KeyStore.getInstance basic provider selection") {
      val keyStore = KeyStore.getInstance("PKCS12")
      assert(keyStore.getType() == "PKCS12")
      assert(keyStore.getProvider() != null)
    }

    test("KeyStore methods should throw if the KeyStore is not loaded yet") {
      val keyStore = KeyStore.getInstance("PKCS12")

      assertThrows[KeyStoreException] {
        keyStore.aliases()
      }

      assertThrows[KeyStoreException] {
        keyStore.size()
      }

      assertThrows[KeyStoreException] {
        keyStore.containsAlias("whatever")
      }
      assertThrows[KeyStoreException] {
        keyStore.containsAlias("1")
      }

      assertThrows[KeyStoreException] {
        keyStore.isCertificateEntry("alias")
      }
      assertThrows[KeyStoreException] {
        keyStore.isKeyEntry("alias")
      }

      assertThrows[KeyStoreException] {
        keyStore.getCertificate("1")
      }
      assertThrows[KeyStoreException] {
        keyStore.getCertificateChain("1")
      }
      assertThrows[KeyStoreException] {
        keyStore.getCreationDate("1")
      }
      assertThrows[KeyStoreException] {
        keyStore.getEntry("1", null)
      }
      assertThrows[KeyStoreException] {
        keyStore.getKey("1", Array.emptyCharArray)
      }
    }

    test("KeyStore use 1 as default alias") {
      val keyStore = KeyStore.getInstance("PKCS12")
      val path = s"${testDataDir}/pkcs12-cert-emptypasswd/testing.p12"
      val stream = new FileInputStream(path)
      try keyStore.load(stream, Array.emptyCharArray)
      finally stream.close()

      val aliases = Collections.list(keyStore.aliases())
      val first = keyStore.getCertificate(aliases.get(0))

      assert(aliases.size() == 1)
      assert(aliases.get(0) == "1")
      assert(first.isInstanceOf[X509Certificate])
      assert(first.getType() == "X.509")

      assert(keyStore.size() == 1)
      assert(keyStore.getCertificateAlias(first) == "1")
    }

    test("KeyStore can load multiple times and should reset previous state") {
      val keyStore = KeyStore.getInstance("PKCS12")

      val path = s"${testDataDir}/pkcs12-cert-emptypasswd/testing.p12"
      val stream = new FileInputStream(path)
      try keyStore.load(stream, Array.emptyCharArray)
      finally stream.close()
      assert(keyStore.size() == 1)
      val firstAlias = keyStore.getCertificate("1")

      val path2 = s"${testDataDir}/pkcs12-cert-passwd/testing.p12"
      val stream2 = new FileInputStream(path2)
      try keyStore.load(stream2, "test-password-for-pkcs12".toCharArray)
      finally stream2.close()
      assert(keyStore.size() == 1)
      val firstAliasReload = keyStore.getCertificate("1")

      assert(firstAlias ne firstAliasReload)
      assert(firstAlias != firstAliasReload)
    }

    test("KeyStore should not reset when failed to load second time") {
      val keyStore = KeyStore.getInstance("PKCS12")

      val path = s"${testDataDir}/pkcs12-cert-emptypasswd/testing.p12"
      val stream = new FileInputStream(path)
      try keyStore.load(stream, Array.emptyCharArray)
      finally stream.close()
      val firstAlias = keyStore.getCertificate("1")

      val path2 = s"${testDataDir}/pkcs12-cert-passwd/testing.p12"
      val stream2 = new FileInputStream(path2)
      try keyStore.load(stream2, Array.emptyCharArray)
      catch { case _: IOException => () }
      finally stream2.close()
      assert(keyStore.size() == 1)
      val firstAliasReload = keyStore.getCertificate("1")

      assert(firstAlias eq firstAliasReload)
      assert(firstAlias == firstAliasReload)
    }

    test("PKCS12 load rejects wrong password with recoverable cause") {
      val keyStore = KeyStore.getInstance("PKCS12")
      val exc = assertThrows[IOException] {
        withFileInputStream(s"${testDataDir}/pkcs12-cert-passwd/testing.p12") {
          stream =>
            keyStore.load(stream, "wrong-password".toCharArray)
        }
      }
      assert(exc.getCause().isInstanceOf[UnrecoverableKeyException])
    }

    test("PKCS12 load rejects empty and malformed input") {
      val keyStoreEmptyStream = KeyStore.getInstance("PKCS12")
      val exc1 = assertThrows[IOException] {
        keyStoreEmptyStream.load(
          new ByteArrayInputStream(Array.emptyByteArray),
          "x".toCharArray
        )
      }
      assert(exc1.getCause() == null)

      val keyStoreMalformed = KeyStore.getInstance("PKCS12")
      val exc2 = assertThrows[IOException] {
        withFileInputStream(
          s"${testDataDir}/x509-cert-pem-noenc/certificate.pem"
        ) { stream =>
          keyStoreMalformed.load(stream, "x".toCharArray)
        }
      }
      assert(exc2.getCause() == null)
    }

    test("PKCS12 load should succeed with correct password and valid input") {
      val ksCertPass = loadPKCS12(
        s"${testDataDir}/pkcs12-cert-passwd/testing.p12",
        "test-password-for-pkcs12".toCharArray
      )
      assert(ksCertPass.size() == 1)
      assert(ksCertPass.getCertificateChain("1").size == 1)

      val ksCertNoPass = loadPKCS12(
        s"${testDataDir}/pkcs12-cert-emptypasswd/testing.p12",
        Array.emptyCharArray
      )
      assert(ksCertNoPass.size() == 1)
      assert(ksCertNoPass.getCertificateChain("1").size == 1)
      val cert = ksCertNoPass.getCertificate("1")
      assert(cert.isInstanceOf[X509Certificate])
      assert(cert.getType() == "X.509")
      assert(ksCertNoPass.getCertificateAlias(cert) == "1")

      val ksChain = loadPKCS12(
        s"${testDataDir}/pkcs12-chain-case-1/testing.p12",
        "test-password-for-pkcs12".toCharArray
      )
      assert(ksChain.size() == 1)
      assert(ksChain.getCertificateChain("1").size == 3)

      val ksBadSSL = loadPKCS12(
        s"${testDataDir}/pkcs12-badssl/badssl.com-client.p12",
        "badssl.com".toCharArray
      )
      assert(ksBadSSL.size() == 1)
      assert(ksBadSSL.getCertificateChain("1").size == 1)
    }

    test(
      "KeyStore can load protection less PKCS#12 file"
    ) {

      test("`load` accept null as empty password") {
        val ksCertNoPass = loadPKCS12(path, null)
        assert(ksCertNoPass.size() == 1)
      }

      val path = s"${testDataDir}/pkcs12-cert-emptypasswd/testing.p12"
      val ksCertNoPass = loadPKCS12(
        path,
        Array.emptyCharArray
      )

      test("`getKey` accept null password") {
        val key = ksCertNoPass.getKey("1", null)
        val key0 = ksCertNoPass.getKey("1", "".toCharArray)
        assert(key == key0)
      }

      test("`getEntry` cannot accept null password") {
        assertThrows[UnrecoverableKeyException] {
          ksCertNoPass.getEntry("1", null)
        }
        val entry =
          ksCertNoPass.getEntry(
            "1",
            new KeyStore.PasswordProtection("".toCharArray())
          )
        assert(entry.isInstanceOf[KeyStore.PrivateKeyEntry])
      }
    }

    test(
      "KeyStore can load PKCS#12 with PrivateKeyEntry and certificate chain"
    ) {
      val passwd = "test-password-for-pkcs12".toCharArray

      val ksChain = loadPKCS12(
        s"${testDataDir}/pkcs12-chain-case-1/testing.p12",
        passwd
      )
      val certs = ksChain.getCertificateChain("1")
      assert(certs.size == 3)
      certs.foreach(cert => {
        assert(cert.isInstanceOf[X509Certificate])
        assert(cert.getType() == "X.509")
      })
      val entry = ksChain.getEntry(
        "1",
        new KeyStore.PasswordProtection(passwd)
      )
      assert(entry.isInstanceOf[KeyStore.PrivateKeyEntry])
    }

    /**
     * KeyStore.PasswordProtection
     */

    test("PasswordProtection supports null password") {
      val protection = new KeyStore.PasswordProtection(null)
      assert(protection.getPassword() == null)

      protection.destroy()
      assert(protection.isDestroyed())
      assertThrows[IllegalStateException] {
        protection.getPassword()
      }
    }

    test("PasswordProtection should throw if protectionAlgorithm is null") {
      assertThrows[NullPointerException] {
        new KeyStore.PasswordProtection("whatever".toCharArray, null, null)
      }
      assertThrows[NullPointerException] {
        new KeyStore.PasswordProtection(null, null, null)
      }
    }

    test(
      "PasswordProtection do not validate protectionAlgorithm is non-empty"
    ) {
      val pass =
        new KeyStore.PasswordProtection("whatever".toCharArray, "", null)
      assert(pass.getProtectionAlgorithm() == "")
    }

    test("PasswordProtection clones input password and supports destroy") {
      val password = "secret-passphrase".toCharArray
      val protection = new KeyStore.PasswordProtection(password)

      password(0) = 'X'
      assert(
        protection.getPassword().sameElements("secret-passphrase".toCharArray)
      )

      val leakedReference = protection.getPassword()
      protection.destroy()

      assert(protection.isDestroyed())
      assert(
        leakedReference.sameElements(Array.fill(leakedReference.length)(' '))
      )
      assertThrows[IllegalStateException] {
        protection.getPassword()
      }
    }

    test("PasswordProtection exposes configured algorithm metadata") {
      val protection =
        new KeyStore.PasswordProtection(
          "secret".toCharArray,
          "PBEWithHmacSHA256AndAES_256", // PBEWithHmacSHA256
          null
        )
      assert(
        protection.getProtectionAlgorithm() == "PBEWithHmacSHA256AndAES_256"
      )
      assert(protection.getProtectionParameters() == null)
    }

  }
}
