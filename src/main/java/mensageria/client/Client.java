package mensageria.client;

import mensageria.common.ByteReader;
import mensageria.common.ByteWriter;
import mensageria.common.Framing;
import mensageria.common.Ids;
import mensageria.common.Protocol;
import mensageria.crypto.AesGcm;
import mensageria.crypto.Fingerprint;
import mensageria.crypto.HandshakeHash;
import mensageria.crypto.HkdfSha256;
import mensageria.crypto.PinnedServerCert;
import mensageria.crypto.RsaPss;
import mensageria.crypto.X25519Util;

import javax.crypto.AEADBadTagException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class Client {

    private final UUID clientId;
    private final KeyPair x25519KeyPair;
    private final byte[] pkClientRaw;
    private final PinnedServerCert pinnedCert;

    private Socket socket;
    private OutputStream out;
    private final Object writeLock = new Object();
    private byte[] saltSrv;

    private final Map<UUID, PeerState> peers = new ConcurrentHashMap<>();
    private volatile boolean running = true;

    public Client(UUID clientId, PinnedServerCert pinnedCert) throws Exception {
        this.clientId = clientId;
        this.pinnedCert = pinnedCert;
        this.x25519KeyPair = X25519Util.generateKeyPair();
        this.pkClientRaw = X25519Util.encodePublicRaw(x25519KeyPair.getPublic());
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("uso: Client <host> <porta> <server.crt> [client_id]");
            System.exit(1);
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String certPath = args[2];
        UUID clientId = args.length > 3 ? UUID.fromString(args[3]) : UUID.randomUUID();

        PinnedServerCert pinnedCert = PinnedServerCert.loadFromFile(certPath);
        Client client = new Client(clientId, pinnedCert);
        client.run(host, port);
    }

    public void run(String host, int port) throws Exception {
        socket = new Socket(host, port);
        socket.setTcpNoDelay(true);
        InputStream in = socket.getInputStream();
        out = socket.getOutputStream();

        System.out.println("[*] client_id local: " + clientId);
        System.out.println("[*] pk_client (fingerprint): " + Fingerprint.of(pkClientRaw));

        sendClientHello();
        doServerHandshake(in);

        Thread reader = new Thread(() -> readLoop(in), "client-reader");
        reader.setDaemon(true);
        reader.start();

        consoleLoop();
    }

    //Handshake

    private void sendClientHello() throws IOException {
        byte[] body = new ByteWriter().bytes(Ids.toBytes(clientId)).bytes(pkClientRaw).toBytes();
        writeFrame(Protocol.CLIENT_HELLO, body);
    }

    private void doServerHandshake(InputStream in) throws Exception {
        byte[] frame = Framing.readFrame(in);
        if (frame == null || frame.length == 0 || frame[0] != Protocol.SERVER_HELLO) {
            throw new IOException("handshake falhou: esperava SERVER_HELLO");
        }
        ByteReader r = new ByteReader(stripType(frame));
        byte[] certDer = r.bytesWithU16Len();
        byte[] signature = r.bytesWithU16Len();
        byte[] salt = r.bytes(Protocol.SALT_LEN);

        // [APRESENTAÇÃO - PARADA 1] Verificação da autenticação do servidor (lado cliente).
        // Duas checagens antes de confiar em qualquer coisa:
        // 1) o certificado recebido é IDÊNTICO (byte a byte) ao que eu já tinha salvo local
        //    (isso é o "pinning" — recusa qualquer outro certificado, mesmo "válido");
        // 2) a assinatura RSA-PSS bate com o hash que eu recalculo aqui.
        // Se qualquer uma falhar, abortamos a conexão na hora.
        if (!pinnedCert.matches(certDer)) {
            throw new SecurityException("certificado do servidor NÃO corresponde ao pinado — possível MITM. Abortando.");
        }

        byte[] h = HandshakeHash.compute(pinnedCert.publicKeyEncoded(), pkClientRaw, Ids.toBytes(clientId), salt);
        boolean valid = RsaPss.verify(pinnedCert.publicKey(), h, signature);
        if (!valid) {
            throw new SecurityException("assinatura RSA-PSS do servidor inválida — abortando handshake.");
        }

        this.saltSrv = salt;
        System.out.println("[*] servidor autenticado com sucesso (certificado pinado + assinatura RSA-PSS válida).");
    }

    //Recepção

    private void readLoop(InputStream in) {
        try {
            while (running) {
                byte[] frame = Framing.readFrame(in);
                if (frame == null) {
                    System.out.println("[*] conexão encerrada pelo servidor.");
                    break;
                }
                if (frame.length == 0) continue;
                byte type = frame[0];
                byte[] body = stripType(frame);
                switch (type) {
                    case Protocol.PEER_ADD -> handlePeerAdd(body);
                    case Protocol.PEER_REMOVE -> handlePeerRemove(body);
                    case Protocol.E2E_FRAME -> handleE2eFrame(body);
                    case Protocol.ERROR_MSG -> handleError(body);
                    default -> System.out.println("[!] frame de tipo desconhecido recebido: " + type);
                }
            }
        } catch (IOException e) {
            if (running) {
                System.out.println("[!] conexão perdida: " + e.getMessage());
            }
        } finally {
            running = false;
        }
    }

    private void handlePeerAdd(byte[] body) throws IOException {
        ByteReader r = new ByteReader(body);
        r.u64(); // seq_no de controle do servidor — não usado pelo E2E
        UUID peerId = Ids.fromBytes(r.bytes(Protocol.CLIENT_ID_LEN), 0);
        byte[] peerPub = r.bytes(Protocol.X25519_PUB_LEN);

        if (peerId.equals(clientId)) return; // defensivo, não deveria ocorrer

        try {
            // [APRESENTAÇÃO - PARADA 2] Segredo compartilhado (ECDH) + derivação (HKDF).
            // ECDH: uso MINHA chave privada + a chave PÚBLICA do peer. O peer faz o mesmo
            // ao contrário (chave privada dele + minha pública). O resultado "z" é IDÊNTICO
            // dos dois lados, mas nunca foi transmitido pela rede — é a mágica do
            // Diffie-Hellman. Essas chaves X25519 são efêmeras (recriadas a cada conexão),
            // o que dá sigilo perfeito (forward secrecy).
            PublicKey peerPublicKey = X25519Util.decodePublicRaw(peerPub);
            PrivateKey sk = x25519KeyPair.getPrivate();
            byte[] z = X25519Util.ecdh(sk, peerPublicKey); // Z_AB — nunca logado, descartado após uso
            byte[] prk = HkdfSha256.extract(saltSrv, z);
            Arrays.fill(z, (byte) 0);

            // HKDF transforma o segredo bruto em DUAS chaves diferentes (uma por direção),
            // só trocando o rótulo "A2B"/"B2A" na fórmula — evita reaproveitar nonce/chave
            // entre as duas direções da conversa.
            boolean localIsA = Ids.isFirst(clientId, peerId);
            byte[] keyA2B = HkdfSha256.expand(prk, "A2B", 16);
            byte[] keyB2A = HkdfSha256.expand(prk, "B2A", 16);
            Arrays.fill(prk, (byte) 0);

            byte[] keySend = localIsA ? keyA2B : keyB2A;
            byte[] keyRecv = localIsA ? keyB2A : keyA2B;

            byte[] ivBaseSend = new byte[Protocol.IV_BASE_LEN];
            new SecureRandom().nextBytes(ivBaseSend);

            PeerState state = new PeerState(peerId, peerPub, keySend, keyRecv, ivBaseSend);
            peers.put(peerId, state);
            System.out.println("[*] chaves E2E derivadas com peer " + peerId
                    + " (pk fingerprint=" + Fingerprint.of(peerPub) + ")");
        } catch (Exception e) {
            System.out.println("[!] falha ao derivar chaves E2E com " + peerId + ": " + e.getMessage());
        }
    }

    private void handlePeerRemove(byte[] body) throws IOException {
        ByteReader r = new ByteReader(body);
        r.u64();
        UUID peerId = Ids.fromBytes(r.bytes(Protocol.CLIENT_ID_LEN), 0);
        if (peers.remove(peerId) != null) {
            System.out.println("[*] peer desconectado: " + peerId);
        }
    }

    private void handleError(byte[] body) throws IOException {
        ByteReader r = new ByteReader(body);
        r.u64();
        int code = r.u8();
        byte[] msg = r.bytesWithU16Len();
        System.out.println("[server ERROR] code=" + code + " msg=" + new String(msg, StandardCharsets.UTF_8));
    }

    private void handleE2eFrame(byte[] body) {
        int minLen = Protocol.NONCE_LEN + Protocol.CLIENT_ID_LEN * 2 + Protocol.SEQ_LEN + Protocol.GCM_TAG_LEN;
        if (body.length < minLen) {
            System.out.println("[!] frame E2E truncado recebido — descartando.");
            return;
        }
        try {
            ByteReader r = new ByteReader(body);
            byte[] nonce = r.bytes(Protocol.NONCE_LEN);
            byte[] senderIdBytes = r.bytes(Protocol.CLIENT_ID_LEN);
            byte[] recipientIdBytes = r.bytes(Protocol.CLIENT_ID_LEN);
            byte[] seqBytes = r.bytes(Protocol.SEQ_LEN);
            byte[] ciphertext = r.rest();

            UUID senderId = Ids.fromBytes(senderIdBytes, 0);
            UUID recipientId = Ids.fromBytes(recipientIdBytes, 0);
            if (!recipientId.equals(clientId)) {
                System.out.println("[!] frame E2E com recipient_id que não é o meu — descartando.");
                return;
            }

            PeerState peer = peers.get(senderId);
            if (peer == null) {
                System.out.println("[!] mensagem de peer desconhecido/sem chaves derivadas (" + senderId + ") — descartando.");
                return;
            }

            long seqNo = beToLong(seqBytes);

            byte[] ivBase = Arrays.copyOfRange(nonce, 0, Protocol.IV_BASE_LEN);
            if (peer.ivBaseRecv == null) {
                peer.ivBaseRecv = ivBase; // trust-on-first-use para esta sessão
            } else if (!Arrays.equals(peer.ivBaseRecv, ivBase)) {
                System.out.println("[!] IV_base inesperado de " + senderId + " — possível ataque, descartando frame.");
                return;
            }

            // Reconstrói o nonce a partir do IV_base conhecido + seq_no recebido e confere
            // contra o nonce transmitido (detecta inconsistência entre os dois campos).
            byte[] reconstructed = new byte[Protocol.NONCE_LEN];
            System.arraycopy(peer.ivBaseRecv, 0, reconstructed, 0, Protocol.IV_BASE_LEN);
            System.arraycopy(seqBytes, 0, reconstructed, Protocol.IV_BASE_LEN, Protocol.SEQ_LEN);
            if (!Arrays.equals(reconstructed, nonce)) {
                System.out.println("[!] nonce reconstruído não confere com o recebido de " + senderId + " — descartando.");
                return;
            }

            // [APRESENTAÇÃO - PARADA 3 (recepção)] Anti-replay: só aceito seq_no
            // ESTRITAMENTE maior que o último aceito desse peer — é isso que faz o
            // MitmProxy em modo "replay" ser rejeitado na 2ª cópia da mesma mensagem.
            if (seqNo <= peer.seqRecv) {
                System.out.println("[!] replay detectado de " + senderId + " (seq_no=" + seqNo + " <= último aceito=" + peer.seqRecv + ") — descartando.");
                return;
            }

            // Se qualquer bit do ciphertext/tag foi alterado no caminho, a tag do GCM não
            // bate e cai no catch abaixo — é isso que faz o MitmProxy em modo "flipbit"
            // ser rejeitado.
            byte[] aad = concat(senderIdBytes, recipientIdBytes, seqBytes);
            byte[] plaintext;
            try {
                plaintext = AesGcm.decrypt(peer.keyRecv, nonce, ciphertext, aad);
            } catch (AEADBadTagException e) {
                System.out.println("[!] tag GCM inválida de " + senderId + " (mensagem adulterada ou chave incorreta) — descartando.");
                return;
            }

            peer.seqRecv = seqNo;
            System.out.println("[" + senderId + "] " + new String(plaintext, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println("[!] erro ao processar frame E2E: " + e.getMessage());
        }
    }

    //Envio

    private void sendTo(UUID peerId, String message) {
        PeerState peer = peers.get(peerId);
        if (peer == null) {
            System.out.println("[!] peer " + peerId + " não encontrado (ainda não conectado ou chaves não derivadas).");
            return;
        }
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
        if (plaintext.length > Protocol.MAX_PLAINTEXT) {
            System.out.println("[!] mensagem excede o limite de " + Protocol.MAX_PLAINTEXT + " bytes.");
            return;
        }
        try {
            // [APRESENTAÇÃO - PARADA 3] Cifragem com AES-128-GCM.
            // Regra do GCM: NUNCA repetir o par (chave, nonce). O nonce aqui é
            // "valor aleatório da sessão (4B) + contador que só sobe (8B)" — nunca se repete
            // dentro da mesma conversa. O "aad" amarra sender/recipient/seq_no à mensagem
            // sem cifrá-los (protegidos pela mesma tag) — impede trocar a etiqueta sem
            // ser percebido.
            long seq = peer.seqSend.getAndIncrement();
            byte[] seqBytes = longToBe(seq);
            byte[] nonce = concat(peer.ivBaseSend, seqBytes);
            byte[] senderIdBytes = Ids.toBytes(clientId);
            byte[] recipientIdBytes = Ids.toBytes(peerId);
            byte[] aad = concat(senderIdBytes, recipientIdBytes, seqBytes);
            byte[] ciphertext = AesGcm.encrypt(peer.keySend, nonce, plaintext, aad);
            byte[] body = concat(nonce, senderIdBytes, recipientIdBytes, seqBytes, ciphertext);
            writeFrame(Protocol.E2E_FRAME, body);
        } catch (Exception e) {
            System.out.println("[!] falha ao enviar mensagem para " + peerId + ": " + e.getMessage());
        }
    }

    //Console

    private void consoleLoop() throws IOException {
        printHelp();
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while (running && (line = stdin.readLine()) != null) {
            line = line.strip();
            if (line.isEmpty()) continue;
            if (line.equals("/quit") || line.equals("/exit")) {
                break;
            } else if (line.equals("/list")) {
                if (peers.isEmpty()) {
                    System.out.println("(nenhum peer com chaves E2E derivadas ainda)");
                } else {
                    peers.values().forEach(p ->
                            System.out.println(" - " + p.peerId + " (fp=" + Fingerprint.of(p.publicKey) + ")"));
                }
            } else if (line.equals("/help")) {
                printHelp();
            } else if (line.startsWith("/all ")) {
                String msg = line.substring(5);
                for (UUID peerId : peers.keySet()) sendTo(peerId, msg);
            } else if (line.startsWith("/send ")) {
                String rest = line.substring(6).strip();
                int sp = rest.indexOf(' ');
                if (sp < 0) {
                    System.out.println("uso: /send <client_id> <mensagem>");
                    continue;
                }
                try {
                    UUID peerId = UUID.fromString(rest.substring(0, sp));
                    sendTo(peerId, rest.substring(sp + 1));
                } catch (IllegalArgumentException e) {
                    System.out.println("client_id inválido.");
                }
            } else {
                System.out.println("comando desconhecido. digite /help.");
            }
        }
        running = false;
        try { socket.close(); } catch (IOException ignored) {}
    }

    private void printHelp() {
        System.out.println("""
                comandos:
                  /list                 lista peers com chaves E2E já derivadas
                  /send <id> <msg>      envia mensagem cifrada E2E para um peer
                  /all <msg>            envia a mensagem para todos os peers conhecidos
                  /quit                 encerra a conexão
                """);
    }

    //Utilitários

    private void writeFrame(byte type, byte[] body) throws IOException {
        byte[] payload = new byte[1 + body.length];
        payload[0] = type;
        System.arraycopy(body, 0, payload, 1, body.length);
        synchronized (writeLock) {
            Framing.writeFrame(out, payload);
        }
    }

    private static byte[] stripType(byte[] frame) {
        return Arrays.copyOfRange(frame, 1, frame.length);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private static byte[] longToBe(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        return b;
    }

    private static long beToLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b[i] & 0xFF);
        }
        return v;
    }
}
