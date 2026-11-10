package mensageria.client;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Estrutura de Dados Mantida pelo Cliente"
 */
final class PeerState {
    final UUID peerId;
    final byte[] publicKey;   // pk do peer, 32 bytes raw X25519
    final byte[] keySend;     // AES-128-GCM — usada para cifrar mensagens enviadas a este peer
    final byte[] keyRecv;     // AES-128-GCM — usada para decifrar mensagens recebidas deste peer
    final byte[] ivBaseSend;  // IV_base (4B) gerado localmente para a direção local -> peer

    final AtomicLong seqSend = new AtomicLong(0);
    volatile long seqRecv = -1;      // anti-replay: último seq_no aceito deste peer
    volatile byte[] ivBaseRecv = null; // aprendido (trust-on-first-use) na primeira mensagem recebida

    PeerState(UUID peerId, byte[] publicKey, byte[] keySend, byte[] keyRecv, byte[] ivBaseSend) {
        this.peerId = peerId;
        this.publicKey = publicKey;
        this.keySend = keySend;
        this.keyRecv = keyRecv;
        this.ivBaseSend = ivBaseSend;
    }
}
