package mensageria.tools;

import mensageria.common.Framing;
import mensageria.common.Protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Proxy TCP didático para demonstrar os testes: bitflip (tag GCM deve falhar) e replay (seq_no já usado deve ser rejeitado).
 */
public final class MitmProxy {

    private enum Mode { NONE, FLIPBIT, REPLAY }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("uso: MitmProxy <porta_local> <host_destino> <porta_destino> [none|flipbit|replay] [n]");
            System.exit(1);
        }
        int localPort = Integer.parseInt(args[0]);
        String targetHost = args[1];
        int targetPort = Integer.parseInt(args[2]);
        Mode mode = args.length > 3 ? Mode.valueOf(args[3].toUpperCase()) : Mode.NONE;
        int n = args.length > 4 ? Integer.parseInt(args[4]) : 1;

        System.out.println("[mitm] escutando em :" + localPort + " -> " + targetHost + ":" + targetPort
                + " (modo=" + mode + (mode != Mode.NONE ? ", n=" + n : "") + ")");

        try (ServerSocket serverSocket = new ServerSocket(localPort)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                Mode finalMode = mode;
                new Thread(() -> handleConnection(clientSocket, targetHost, targetPort, finalMode, n)).start();
            }
        }
    }

    private static void handleConnection(Socket clientSocket, String targetHost, int targetPort, Mode mode, int n) {
        try (Socket serverSocket = new Socket(targetHost, targetPort)) {
            System.out.println("[mitm] nova conexão: " + clientSocket.getRemoteSocketAddress());
            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();
            InputStream serverIn = serverSocket.getInputStream();
            OutputStream serverOut = serverSocket.getOutputStream();
            Thread t1 = new Thread(() -> pump(clientIn, serverOut, "C->S", mode, n));
            Thread t2 = new Thread(() -> pump(serverIn, clientOut, "S->C", Mode.NONE, 0));
            t1.start();
            t2.start();
            t1.join();
            t2.join();
        } catch (Exception e) {
            System.out.println("[mitm] conexão encerrada: " + e.getMessage());
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    private static void pump(InputStream in, OutputStream out, String direction, Mode mode, int n) {
        AtomicInteger e2eCount = new AtomicInteger(0);
        try {
            while (true) {
                byte[] frame = Framing.readFrame(in);
                if (frame == null) return;

                boolean isE2e = frame.length > 0 && frame[0] == Protocol.E2E_FRAME;
                int count = isE2e ? e2eCount.incrementAndGet() : -1;

                if (mode == Mode.FLIPBIT && count == n) {
                    frame = flipLastBit(frame);
                    System.out.println("[mitm] " + direction + ": bit invertido no ciphertext do E2E_FRAME #" + count);
                }

                Framing.writeFrame(out, frame);

                if (mode == Mode.REPLAY && count == n) {
                    Framing.writeFrame(out, frame); // reenvia o mesmo frame (mesmo seq_no) em seguida
                    System.out.println("[mitm] " + direction + ": E2E_FRAME #" + count + " reenviado (replay)");
                }
            }
        } catch (IOException e) {
            // conexão encerrada (normal ao fechar o cliente/servidor)
        }
    }

    private static byte[] flipLastBit(byte[] frame) {
        byte[] copy = frame.clone();
        copy[copy.length - 1] ^= 0x01; // último byte faz parte da tag GCM
        return copy;
    }
}
