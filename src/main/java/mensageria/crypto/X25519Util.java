package mensageria.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import javax.crypto.KeyAgreement;

/**
 * ECDHE com X25519 usando apenas a API padrão do JDK.
 * As chaves públicas trafegam como 32 bytes "raw" (RFC 7748). Esta classe cuida da conversão entre o
 * formato raw e os objetos {@link PublicKey}/{@link PrivateKey} do JDK.
 */
public final class X25519Util {
    private static final String ALG = "X25519";
    private static final NamedParameterSpec SPEC = new NamedParameterSpec(ALG);

    private X25519Util() {}

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALG);
        return kpg.generateKeyPair();
    }

    /** Codifica a chave pública X25519 como 32 bytes raw little-endian (RFC 7748). */
    public static byte[] encodePublicRaw(PublicKey pub) {
        XECPublicKey xpk = (XECPublicKey) pub;
        byte[] be = toFixedLengthBigEndian(xpk.getU(), 32);
        return reverse(be);
    }

    /** Decodifica 32 bytes raw little-endian em um {@link PublicKey} X25519. */
    public static PublicKey decodePublicRaw(byte[] raw32) throws GeneralSecurityException {
        if (raw32.length != 32) {
            throw new IllegalArgumentException("chave pública X25519 deve ter 32 bytes, recebeu " + raw32.length);
        }
        byte[] clamped = raw32.clone();
        // RFC 7748 decodeUCoordinate: para X25519 (255 bits), o bit mais significativo do
        // último byte (representação little-endian) é ignorado/zerado na decodificação.
        clamped[31] &= 0x7F;
        byte[] be = reverse(clamped);
        BigInteger u = new BigInteger(1, be);
        KeyFactory kf = KeyFactory.getInstance(ALG);
        return kf.generatePublic(new XECPublicKeySpec(SPEC, u));
    }

    /** Z_AB = ECDH(sk_A, pk_B): segredo compartilhado bruto, usado como IKM do HKDF. */
    public static byte[] ecdh(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance(ALG);
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    private static byte[] toFixedLengthBigEndian(BigInteger value, int length) {
        byte[] raw = value.toByteArray(); // big-endian, pode ter byte de sinal extra ou ser mais curto
        byte[] out = new byte[length];
        int srcStart = Math.max(0, raw.length - length);
        int copyLen = raw.length - srcStart;
        System.arraycopy(raw, srcStart, out, length - copyLen, copyLen);
        return out;
    }

    private static byte[] reverse(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return out;
    }
}
