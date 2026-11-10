package mensageria.common;

import java.io.IOException;

/** Lê sequencialmente o corpo binário de um frame, validando limites. */
public final class ByteReader {
    private final byte[] data;
    private int pos;

    public ByteReader(byte[] data) {
        this.data = data;
        this.pos = 0;
    }

    private void require(int n) throws IOException {
        if (pos + n > data.length) {
            throw new IOException("framing inválido: frame truncado (esperava mais " + n + " bytes)");
        }
    }

    public int u8() throws IOException {
        require(1);
        return data[pos++] & 0xFF;
    }

    public int u16() throws IOException {
        require(2);
        int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    public long u64() throws IOException {
        require(8);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (data[pos + i] & 0xFF);
        }
        pos += 8;
        return v;
    }

    public byte[] bytes(int n) throws IOException {
        require(n);
        byte[] out = new byte[n];
        System.arraycopy(data, pos, out, 0, n);
        pos += n;
        return out;
    }

    public byte[] bytesWithU16Len() throws IOException {
        int len = u16();
        return bytes(len);
    }

    public byte[] rest() {
        byte[] out = new byte[data.length - pos];
        System.arraycopy(data, pos, out, 0, out.length);
        pos = data.length;
        return out;
    }

    public boolean hasRemaining() {
        return pos < data.length;
    }
}
