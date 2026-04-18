package scalanativecrypto

import utest._
import java.security._

/**
 * Tests for Ed25519 signature generation and verification via
 * java.security.Signature and java.security.KeyPairGenerator.
 */
object Ed25519Suite extends TestSuite {

  // Helper to compare byte arrays without utest dumping them on failure
  private def arraysEqual(a: Array[Byte], b: Array[Byte]): Boolean =
    a.length == b.length && a.indices.forall(i => a(i) == b(i))

  val tests = Tests {
    test("KeyPairGenerator") {
      test("getInstance returns Ed25519 generator") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val algo = kpg.getAlgorithm()
        assert(algo == "Ed25519" || algo == "EdDSA")
      }

      test("generates a key pair") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        assert(kp.getPublic() != null)
        assert(kp.getPrivate() != null)
        val algo = kp.getPublic().getAlgorithm()
        assert(algo == "Ed25519" || algo == "EdDSA")
        assert(kp.getPublic().getEncoded().length >= 32)
        assert(kp.getPrivate().getEncoded().length >= 32)
      }

      test("generates different key pairs each time") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp1 = kpg.generateKeyPair()
        val kp2 = kpg.generateKeyPair()
        val different = !arraysEqual(kp1.getPublic().getEncoded(), kp2.getPublic().getEncoded())
        assert(different)
      }

      test("EdDSA alias works") {
        val kpg = KeyPairGenerator.getInstance("EdDSA")
        val algo = kpg.getAlgorithm()
        assert(algo == "Ed25519" || algo == "EdDSA")
      }
    }

    test("Signature") {
      test("sign and verify roundtrip") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = "hello world".getBytes("UTF-8")

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp.getPrivate())
        signer.update(data)
        val sig = signer.sign()
        assert(sig.length == 64)

        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp.getPublic())
        verifier.update(data)
        assert(verifier.verify(sig))
      }

      test("verify fails with wrong public key") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp1 = kpg.generateKeyPair()
        val kp2 = kpg.generateKeyPair()
        val data = "test data".getBytes("UTF-8")

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp1.getPrivate())
        signer.update(data)
        val sig = signer.sign()

        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp2.getPublic())
        verifier.update(data)
        assert(!verifier.verify(sig))
      }

      test("verify fails with tampered data") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = "original data".getBytes("UTF-8")

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp.getPrivate())
        signer.update(data)
        val sig = signer.sign()

        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp.getPublic())
        verifier.update("tampered data".getBytes("UTF-8"))
        assert(!verifier.verify(sig))
      }

      test("verify fails with tampered signature") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = "test".getBytes("UTF-8")

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp.getPrivate())
        signer.update(data)
        val sig = signer.sign()

        val tampered = sig.clone()
        tampered(0) = (tampered(0) ^ 0xff).toByte

        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp.getPublic())
        verifier.update(data)
        // Some implementations throw SignatureException instead of returning false
        val verified = try { verifier.verify(tampered) } catch { case _: SignatureException => false }
        assert(!verified)
      }

      test("Ed25519 is deterministic") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = "deterministic".getBytes("UTF-8")

        val signer1 = Signature.getInstance("Ed25519")
        signer1.initSign(kp.getPrivate())
        signer1.update(data)
        val sig1 = signer1.sign()

        val signer2 = Signature.getInstance("Ed25519")
        signer2.initSign(kp.getPrivate())
        signer2.update(data)
        val sig2 = signer2.sign()

        assert(arraysEqual(sig1, sig2))
      }

      test("different keys produce different signatures") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp1 = kpg.generateKeyPair()
        val kp2 = kpg.generateKeyPair()
        val data = "same data".getBytes("UTF-8")

        val signer1 = Signature.getInstance("Ed25519")
        signer1.initSign(kp1.getPrivate())
        signer1.update(data)
        val sig1 = signer1.sign()

        val signer2 = Signature.getInstance("Ed25519")
        signer2.initSign(kp2.getPrivate())
        signer2.update(data)
        val sig2 = signer2.sign()

        assert(!arraysEqual(sig1, sig2))
      }

      test("sign and verify empty message") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp.getPrivate())
        signer.update(Array.empty[Byte])
        val sig = signer.sign()

        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp.getPublic())
        verifier.update(Array.empty[Byte])
        assert(verifier.verify(sig))
      }

      test("sign and verify large message") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = new Array[Byte](100000)
        new SecureRandom().nextBytes(data)

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp.getPrivate())
        signer.update(data)
        val sig = signer.sign()

        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp.getPublic())
        verifier.update(data)
        assert(verifier.verify(sig))
      }

      test("incremental update equals single update") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = "hello world test data".getBytes("UTF-8")

        val signer1 = Signature.getInstance("Ed25519")
        signer1.initSign(kp.getPrivate())
        signer1.update(data)
        val sig1 = signer1.sign()

        val signer2 = Signature.getInstance("Ed25519")
        signer2.initSign(kp.getPrivate())
        signer2.update("hello ".getBytes("UTF-8"))
        signer2.update("world ".getBytes("UTF-8"))
        signer2.update("test data".getBytes("UTF-8"))
        val sig2 = signer2.sign()

        assert(arraysEqual(sig1, sig2))
      }

      test("EdDSA alias works for Signature") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val data = "alias test".getBytes("UTF-8")

        val signer = Signature.getInstance("EdDSA")
        signer.initSign(kp.getPrivate())
        signer.update(data)
        val sig = signer.sign()

        val verifier = Signature.getInstance("EdDSA")
        verifier.initVerify(kp.getPublic())
        verifier.update(data)
        assert(verifier.verify(sig))
      }

      test("sign without init throws") {
        val signer = Signature.getInstance("Ed25519")
        val threw = try { signer.sign(); false } catch { case _: SignatureException => true }
        assert(threw)
      }

      test("verify without init throws") {
        val verifier = Signature.getInstance("Ed25519")
        val threw = try { verifier.verify(new Array[Byte](64)); false } catch { case _: SignatureException => true }
        assert(threw)
      }

      test("reuse signer for multiple signatures") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()

        val signer = Signature.getInstance("Ed25519")
        signer.initSign(kp.getPrivate())
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(kp.getPublic())

        signer.update("message 1".getBytes("UTF-8"))
        val sig1 = signer.sign()
        verifier.update("message 1".getBytes("UTF-8"))
        assert(verifier.verify(sig1))

        signer.update("message 2".getBytes("UTF-8"))
        val sig2 = signer.sign()
        verifier.update("message 2".getBytes("UTF-8"))
        assert(verifier.verify(sig2))

        assert(!arraysEqual(sig1, sig2))
      }
    }

    test("key export") {
      test("public key export is consistent") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val exported1 = kp.getPublic().getEncoded()
        val exported2 = kp.getPublic().getEncoded()
        assert(exported1.length >= 32)
        assert(arraysEqual(exported1, exported2))
      }

      test("private key export is consistent") {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val exported1 = kp.getPrivate().getEncoded()
        val exported2 = kp.getPrivate().getEncoded()
        assert(exported1.length >= 32)
        assert(arraysEqual(exported1, exported2))
      }
    }
  }
}
