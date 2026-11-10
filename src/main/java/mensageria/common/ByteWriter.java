package mensageria.common;

import java.io.ByteArrayOutputStream;

/** Monta o corpo binário de um frame de forma incremental. */
public final class ByteWriter {
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    public ByteWriter u8(int v) {
        buf.write(v & 0xFF);
        return this;
    }

    public ByteWriter u16(int v) {
        buf.write((v >>> 8) & 0xFF);
        buf.write(v & 0xFF);
        return this;
    }

    public ByteWriter u64(long v) {
        for (int i = 7; i >= 0; i--) {
            buf.write((int) (v >>> (8 * i)) & 0xFF);
        }
        return this;
    }

    public ByteWriter bytes(byte[] b) {
        buf.write(b, 0, b.length);
        return this;
    }

    public ByteWriter bytesWithU16Len(byte[] b) {
        u16(b.length);
        bytes(b);
        return this;
    }

    public byte[] toBytes() {
        return buf.toByteArray();
    }
}
