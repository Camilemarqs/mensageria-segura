package mensageria.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Assinatura RSA-PSS com SHA-256, usada pelo servidor para provar autenticidade e evitar MITM
 * no registro das chaves públicas.
 */
public final class RsaPss {
    private static final String SIG_ALG = "RSASSA-PSS";
    // saltLen=32 (tamanho do hash SHA-256), trailerField=1 (0xBC), conforme PKCS#1 v2.1 / padrão RSA-PSS.
    private static final PSSParameterSpec PSS_SPEC =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    private RsaPss() {}

    public static byte[] sign(PrivateKey sk, byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIG_ALG);
        sig.setParameter(PSS_SPEC);
        sig.initSign(sk);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(PublicKey pk, byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIG_ALG);
        sig.setParameter(PSS_SPEC);
        sig.initVerify(pk);
        sig.update(data);
        return sig.verify(signature);
    }
}
