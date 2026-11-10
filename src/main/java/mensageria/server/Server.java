package mensageria.server;

import mensageria.common.ByteReader;
import mensageria.common.Framing;
import mensageria.common.Ids;
import mensageria.common.Protocol;
import mensageria.crypto.Fingerprint;
import mensageria.crypto.HandshakeHash;
import mensageria.crypto.RsaPss;
import mensageria.crypto.ServerIdentity;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class Server {

    private final ServerIdentity identity;
    private final ConcurrentHashMap<UUID, ClientSession> sessions = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    // salt_srv é compartilhado por todos os clientes da "época" atual (enquanto houver pelo
    // menos um cliente conectado), e não por conexão individual. Isso é necessário porque dois
    // peers distintos (A e B) precisam chegar ao MESMO PRK = HKDF-Extract(salt_srv, Z_AB) para
    // que Key_A2B/Key_B2A batem dos dois lados — um salt por-conexão faria cada lado derivar
    // chaves diferentes. O salt é rotacionado quando o último cliente se desconecta, então uma
    // nova "época" (novo conjunto de clientes) nunca reutiliza o salt de uma época anterior; a
    // propriedade de "não reutilizar segredo anterior" em reconexões fica garantida pelas chaves
    // ECDHE efêmeras, que são sempre recriadas a cada conexão do cliente.
    private volatile byte[] currentSalt = freshSalt(new SecureRandom());

    public Server(ServerIdentity identity) {
        this.identity = identity;
    }

    private static byte[] freshSalt(SecureRandom random) {
        byte[] salt = new byte[Protocol.SALT_LEN];
        random.nextBytes(salt);
        return salt;
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9000;
        String keystorePath = args.length > 1 ? args[1] : "server.p12";
        char[] password = (args.length > 2 ? args[2] : "changeit").toCharArray();
        String alias = args.length > 3 ? args[3] : "server";

        ServerIdentity identity = ServerIdentity.load(keystorePath, password, alias);
        new Server(identity).run(port);
    }

    public void run(int port) throws IOException {
        // Thread pool clássico.
        ExecutorService pool = Executors.newCachedThreadPool();
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            log("servidor iniciado na porta " + port + " (fingerprint da chave pública: "
                    + Fingerprint.of(identity.publicKeyEncoded()) + ")");
            while (true) {
                Socket socket = serverSocket.accept();
                pool.submit(() -> handleClient(socket));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private void handleClient(Socket socket) {
        UUID clientId = null;
        ClientSession session = null;
        try {
            socket.setTcpNoDelay(true);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            byte[] frame = Framing.readFrame(in);
            if (frame == null || frame.length == 0 || frame[0] != Protocol.CLIENT_HELLO) {
                log("conexão rejeitada: primeiro frame não é CLIENT_HELLO (" + socket.getRemoteSocketAddress() + ")");
                return;
            }
            ByteReader r = new ByteReader(stripType(frame));
            byte[] clientIdBytes = r.bytes(Protocol.CLIENT_ID_LEN);
            byte[] pkClient = r.bytes(Protocol.X25519_PUB_LEN);
            clientId = Ids.fromBytes(clientIdBytes, 0);

            // Reconexão com o mesmo client_id: limpa sessão antiga, handshake completo é refeito
            // e um novo salt_srv é gerado (não reutiliza salt/seq_no anteriores).
            ClientSession previous = sessions.remove(clientId);
            if (previous != null) {
                log("client_id " + clientId + " reconectou: sessão anterior encerrada");
                previous.closeQuietly();
            }

            byte[] salt = currentSalt;

            // [APRESENTAÇÃO - PARADA 1] Autenticação do servidor.
            // Calculo um hash dos dados do handshake e assino com a chave PRIVADA RSA do
            // servidor. Só quem tem essa chave privada consegue gerar essa assinatura — é
            // o que prova pro cliente que ele está falando com o servidor de verdade.
            byte[] h = HandshakeHash.compute(identity.publicKeyEncoded(), pkClient, clientIdBytes, salt);
            byte[] signature;
            try {
                signature = RsaPss.sign(identity.privateKey(), h);
            } catch (Exception e) {
                log("falha ao assinar handshake para " + clientId + ": " + e.getMessage());
                return;
            }

            session = new ClientSession(clientId, socket, out, pkClient, salt);

            byte[] serverHelloBody = new mensageria.common.ByteWriter()
                    .bytesWithU16Len(identity.certDer())
                    .bytesWithU16Len(signature)
                    .bytes(salt)
                    .toBytes();
            session.sendRaw(Protocol.SERVER_HELLO, serverHelloBody);

            // Notifica peers existentes sobre o novo cliente e vice-versa (passos 4-6 do fluxo).
            List<ClientSession> existing = new ArrayList<>(sessions.values());
            sessions.put(clientId, session);
            for (ClientSession peer : existing) {
                if (!peer.open) continue;
                try {
                    peer.sendPeerAdd(clientId, pkClient);
                } catch (IOException e) {
                    log("falha ao notificar " + peer.clientId + " sobre novo peer: " + e.getMessage());
                }
                session.sendPeerAdd(peer.clientId, peer.publicKey);
            }

            log("cliente registrado: " + clientId + " (fingerprint pk: " + Fingerprint.of(pkClient) + ")");

            readLoop(session, in);
        } catch (IOException e) {
            log("erro de conexão" + (clientId != null ? " (" + clientId + ")" : "") + ": " + e.getMessage());
        } finally {
            if (clientId != null) {
                ClientSession removed = sessions.remove(clientId);
                if (removed != null) {
                    removed.closeQuietly();
                    broadcastPeerRemove(clientId);
                    log("cliente desconectado: " + clientId);
                    if (sessions.isEmpty()) {
                        currentSalt = freshSalt(random);
                        log("todos os clientes desconectados — salt_srv rotacionado para a próxima época");
                    }
                }
            } else {
                try { socket.close(); } catch (IOException ignored) {}
            }
        }
    }

    private void readLoop(ClientSession session, InputStream in) throws IOException {
        while (session.open) {
            byte[] frame = Framing.readFrame(in);
            if (frame == null) {
                return; // EOF limpo
            }
            if (frame.length == 0) {
                session.sendError(1, "frame vazio");
                return;
            }
            byte type = frame[0];
            if (type != Protocol.E2E_FRAME) {
                session.sendError(2, "tipo de frame inesperado do cliente: " + type);
                return;
            }
            handleE2eFrame(session, stripType(frame));
        }
    }

    private void handleE2eFrame(ClientSession sender, byte[] body) throws IOException {
        // [nonce(12)] [sender_id(16)] [recipient_id(16)] [seq_no(8)] [ciphertext+tag(var)]
        int minLen = Protocol.NONCE_LEN + Protocol.CLIENT_ID_LEN * 2 + Protocol.SEQ_LEN + Protocol.GCM_TAG_LEN;
        if (body.length < minLen) {
            sender.sendError(3, "frame E2E truncado");
            throw new IOException("frame E2E menor que o mínimo esperado");
        }
        int maxLen = Protocol.NONCE_LEN + Protocol.CLIENT_ID_LEN * 2 + Protocol.SEQ_LEN
                + Protocol.MAX_PLAINTEXT + Protocol.GCM_TAG_LEN;
        if (body.length > maxLen) {
            sender.sendError(4, "frame E2E excede o tamanho máximo de plaintext permitido");
            throw new IOException("frame E2E maior que o máximo permitido");
        }

        ByteReader r = new ByteReader(body);
        r.bytes(Protocol.NONCE_LEN); // nonce — não inspecionado pelo servidor
        byte[] senderIdBytes = r.bytes(Protocol.CLIENT_ID_LEN);
        byte[] recipientIdBytes = r.bytes(Protocol.CLIENT_ID_LEN);
        UUID senderId = Ids.fromBytes(senderIdBytes, 0);
        UUID recipientId = Ids.fromBytes(recipientIdBytes, 0);

        if (!senderId.equals(sender.clientId)) {
            sender.sendError(5, "sender_id do frame não corresponde ao client_id autenticado");
            throw new IOException("tentativa de spoofing de sender_id por " + sender.clientId);
        }

        ClientSession recipient = sessions.get(recipientId);
        if (recipient == null || !recipient.open) {
            sender.sendError(6, "destinatário não conectado");
            return; // não derruba a conexão do remetente por causa disso
        }

        // [APRESENTAÇÃO - PARADA 4] Relay puro.
        // Isso é praticamente tudo que o servidor faz com uma mensagem: olha o
        // recipient_id pra saber pra quem mandar, e repassa os bytes EXATAMENTE como
        // chegaram. Nenhuma chamada de decifrar aqui — a chave simétrica foi calculada
        // só dentro de A e B (Parada 2), o servidor nunca teve acesso a ela.
        recipient.relayE2eFrame(body);
        log("relay " + senderId + " -> " + recipientId + " (" + body.length + " bytes)");
    }

    private void broadcastPeerRemove(UUID clientId) {
        for (ClientSession s : sessions.values()) {
            try {
                s.sendPeerRemove(clientId);
            } catch (IOException e) {
                log("falha ao notificar " + s.clientId + " sobre desconexão de " + clientId + ": " + e.getMessage());
            }
        }
    }

    private static byte[] stripType(byte[] frame) {
        byte[] body = new byte[frame.length - 1];
        System.arraycopy(frame, 1, body, 0, body.length);
        return body;
    }

    private static void log(String msg) {
        System.out.println("[server] " + msg);
    }
}
