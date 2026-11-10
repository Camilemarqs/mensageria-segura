package mensageria.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * H = SHA256(pk_server || pk_client || client_id || salt), conforme
 */
public final class HandshakeHash {
    private HandshakeHash() {}

    public static byte[] compute(byte[] pkServerEncoded, byte[] pkClientRaw, byte[] clientId16, byte[] salt16) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(pkServerEncoded);
            sha256.update(pkClientRaw);
            sha256.update(clientId16);
            sha256.update(salt16);
            return sha256.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 indisponível na JVM", e);
        }
    }
}
