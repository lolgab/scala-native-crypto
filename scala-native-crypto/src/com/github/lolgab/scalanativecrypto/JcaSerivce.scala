package com.github.lolgab.scalanativecrypto

// Java Cryptography Architecture (JCA) Service identifier
// for better type safety
class JcaService(
    val name: String
) extends AnyVal

object JcaService {
  val AlgorithmParameterGenerator = new JcaService(
    "AlgorithmParameterGenerator"
  )
  val AlgorithmParameters = new JcaService("AlgorithmParameters")
  val CertificateFactory = new JcaService("CertificateFactory")
  val CertPath = new JcaService("CertPath")
  val CertPathBuilder = new JcaService("CertPathBuilder")
  val CertPathValidator = new JcaService("CertPathValidator")
  val CertStore = new JcaService("CertStore")
  val Cipher = new JcaService("Cipher")
  val KeyAgreement = new JcaService("KeyAgreement")
  val KeyFactory = new JcaService("KeyFactory")
  val KeyGenerator = new JcaService("KeyGenerator")
  val KeyPairGenerator = new JcaService("KeyPairGenerator")
  val KeyStore = new JcaService("KeyStore")
  val Mac = new JcaService("Mac")
  val MessageDigest = new JcaService("MessageDigest")
  val SecretKeyFactory = new JcaService("SecretKeyFactory")
  val SecureRandom = new JcaService("SecureRandom")
  val Signature = new JcaService("Signature")

  val allNames: Set[String] = Set(
    AlgorithmParameterGenerator.name,
    AlgorithmParameters.name,
    CertificateFactory.name,
    CertPath.name,
    CertPathBuilder.name,
    CertPathValidator.name,
    CertStore.name,
    Cipher.name,
    KeyAgreement.name,
    KeyFactory.name,
    KeyGenerator.name,
    KeyPairGenerator.name,
    KeyStore.name,
    Mac.name,
    MessageDigest.name,
    SecretKeyFactory.name,
    SecureRandom.name,
    Signature.name
  ).map(_.toUpperCase())
}
