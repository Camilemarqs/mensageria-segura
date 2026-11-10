package mensageria.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Fingerprint curto (hex) de uma chave, para uso em logs de debug
 */
public final class Fingerprint {
    private Fingerprint() {}

    public static String of(byte[] data) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(data);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                sb.append(String.format("%02x", digest[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 indisponível na JVM", e);
        }
    }
}
