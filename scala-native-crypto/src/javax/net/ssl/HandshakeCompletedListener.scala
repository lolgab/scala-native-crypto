package javax.net.ssl

import java.util.EventListener

trait HandshakeCompletedListener extends EventListener {
  def handshakeCompleted(event: HandshakeCompletedEvent): Unit
}
