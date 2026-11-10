package mensageria.server;

import mensageria.common.ByteWriter;
import mensageria.common.Framing;
import mensageria.common.Ids;
import mensageria.common.Protocol;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Estrutura de Dados no Servidor.
 */

final class ClientSession {
    final UUID clientId;
    final Socket socket;
    final OutputStream out;
    final byte[] publicKey; // pk_C, 32 bytes raw X25519
    final byte[] salt;      // salt_srv (16B) gerado neste handshake — nunca logado

    private final Object writeLock = new Object();
    private final AtomicLong seqSend = new AtomicLong(0); // mensagens de controle S->C
    volatile boolean open = true;

    ClientSession(UUID clientId, Socket socket, OutputStream out, byte[] publicKey, byte[] salt) {
        this.clientId = clientId;
        this.socket = socket;
        this.out = out;
        this.publicKey = publicKey;
        this.salt = salt;
    }

    /** Envia um frame de controle (PEER_ADD/PEER_REMOVE/ERROR) com seq_no monotônico. */
    void sendControlFrame(byte type, ByteWriter bodyWithoutSeq) throws IOException {
        long seq = seqSend.getAndIncrement();
        ByteWriter w = new ByteWriter().u64(seq).bytes(bodyWithoutSeq.toBytes());
        sendRaw(type, w.toBytes());
    }

    /** Relay de um frame E2E — encaminhado byte a byte, sem decifrar (o servidor não possui as chaves). */
    void relayE2eFrame(byte[] originalBody) throws IOException {
        sendRaw(Protocol.E2E_FRAME, originalBody);
    }

    void sendRaw(byte type, byte[] body) throws IOException {
        byte[] payload = new byte[1 + body.length];
        payload[0] = type;
        System.arraycopy(body, 0, payload, 1, body.length);
        synchronized (writeLock) {
            Framing.writeFrame(out, payload);
        }
    }

    void sendPeerAdd(UUID peerId, byte[] peerPubKey) throws IOException {
        ByteWriter body = new ByteWriter().bytes(Ids.toBytes(peerId)).bytes(peerPubKey);
        sendControlFrame(Protocol.PEER_ADD, body);
    }

    void sendPeerRemove(UUID peerId) throws IOException {
        ByteWriter body = new ByteWriter().bytes(Ids.toBytes(peerId));
        sendControlFrame(Protocol.PEER_REMOVE, body);
    }

    void sendError(int code, String message) throws IOException {
        byte[] msg = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteWriter body = new ByteWriter().u8(code).bytesWithU16Len(msg);
        sendControlFrame(Protocol.ERROR_MSG, body);
    }

    void closeQuietly() {
        open = false;
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
