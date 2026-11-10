package mensageria.common;

import java.nio.ByteBuffer;
import java.util.UUID;

/** Conversão entre UUID v4 e sua representação binária de 16 bytes */
public final class Ids {
    private Ids() {}

    public static byte[] toBytes(UUID id) {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putLong(id.getMostSignificantBits());
        bb.putLong(id.getLeastSignificantBits());
        return bb.array();
    }

    public static UUID fromBytes(byte[] b, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(b, offset, 16);
        long hi = bb.getLong();
        long lo = bb.getLong();
        return new UUID(hi, lo);
    }

    /** Ordem determinística entre dois client_id, usada para decidir o rótulo "A"/"B" na
     *  derivação HKDF (labels "A2B"/"B2A"), de forma que ambos os lados cheguem ao mesmo
     *  resultado sem precisar negociar quem é A e quem é B. */
    public static boolean isFirst(UUID a, UUID b) {
        return a.compareTo(b) < 0;
    }
}
