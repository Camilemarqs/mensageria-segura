package mensageria.common;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class Framing {
    private Framing() {}


    public static void writeFrame(OutputStream out, byte[] payload) throws IOException {
        if (payload.length > Protocol.MAX_FRAME_LEN) {
            throw new IOException("frame excede o tamanho máximo permitido: " + payload.length);
        }
        byte[] header = new byte[4];
        header[0] = (byte) (payload.length >>> 24);
        header[1] = (byte) (payload.length >>> 16);
        header[2] = (byte) (payload.length >>> 8);
        header[3] = (byte) (payload.length);
        out.write(header);
        out.write(payload);
        out.flush();
    }

    public static byte[] readFrame(InputStream in) throws IOException {
        DataInputStream dis = (in instanceof DataInputStream) ? (DataInputStream) in : new DataInputStream(in);
        int len;
        try {
            len = dis.readInt();
        } catch (EOFException e) {
            return null; // conexão encerrada de forma limpa entre frames
        }
        if (len < 0 || len > Protocol.MAX_FRAME_LEN) {
            throw new IOException("framing inválido: tamanho de frame fora do intervalo permitido (" + len + ")");
        }
        byte[] payload = new byte[len];
        dis.readFully(payload);
        return payload;
    }
}
