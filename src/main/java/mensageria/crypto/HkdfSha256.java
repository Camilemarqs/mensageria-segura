package mensageria.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** HKDF (RFC 5869) com HMAC-SHA256 */
public final class HkdfSha256 {
    private static final String HMAC_ALG = "HmacSHA256";
    public static final int HASH_LEN = 32;

    private HkdfSha256() {}

    /** PRK = HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM) */
    public static byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(new SecretKeySpec(salt, HMAC_ALG));
        return mac.doFinal(ikm);
    }

    /** OKM = HKDF-Expand(PRK, info, L) */
    public static byte[] expand(byte[] prk, String info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(new SecretKeySpec(prk, HMAC_ALG));
        byte[] infoBytes = info.getBytes(StandardCharsets.US_ASCII);

        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < length) {
            mac.reset();
            mac.update(t);
            mac.update(infoBytes);
            mac.update((byte) counter);
            t = mac.doFinal();
            int copy = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, okm, pos, copy);
            pos += copy;
            counter++;
        }
        return okm;
    }
}
