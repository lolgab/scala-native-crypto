package javax.net.ssl

import java.util.EventObject
import java.security.cert.Certificate
import java.security.Principal
import java.security.cert.X509Certificate

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/javax/net/ssl/HandshakeCompletedEvent.html
class HandshakeCompletedEvent(sock: SSLSocket, session: SSLSession)
    extends EventObject(sock) {

  def getSession(): SSLSession = session

  def getCipherSuite(): String = session.getCipherSuite()

  def getLocalCertificates(): Array[Certificate] =
    session.getLocalCertificates()

  @throws[SSLPeerUnverifiedException]
  def getPeerCertificates(): Array[Certificate] = session.getPeerCertificates()

  // `getPeerCertificateChain` deprecated since Java 9
  // def getPeerCertificateChain(): Array[X509Certificate]

  @throws[SSLPeerUnverifiedException]
  def getPeerPrincipal(): Principal = {
    try {
      session.getPeerPrincipal()
    } catch {
      case _: AbstractMethodError =>
        val certs = getPeerCertificates()
        certs(0).asInstanceOf[X509Certificate].getSubjectX500Principal()
    }
  }

  def getLocalPrincipal(): Principal = {
    try {
      session.getLocalPrincipal()
    } catch {
      case _: AbstractMethodError =>
        val certs = getLocalCertificates()
        certs(0).asInstanceOf[X509Certificate].getSubjectX500Principal()
    }
  }

  def getSocket(): SSLSocket = getSource().asInstanceOf[SSLSocket]
}
