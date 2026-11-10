package mensageria.crypto;

import mensageria.common.Protocol;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AES-128-GCM (AEAD)
 * [APRESENTAÇÃO - PARADA 3] Essas são as DUAS ÚNICAS funções que fazem a cifragem de
 * verdade em todo o projeto. Tudo nas Paradas 1 e 2 (handshake + ECDH/HKDF) existe só
 * pra conseguir chegar numa "key" segura pra passar aqui dentro.
 */
public final class AesGcm {
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int TAG_BITS = Protocol.GCM_TAG_LEN * 8;

    private AesGcm() {}

    /** @return ciphertext com a tag de 16 bytes concatenada ao final (comportamento padrão do JCE). */
    public static byte[] encrypt(byte[] key16, byte[] nonce12, byte[] plaintext, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key16, "AES"), new GCMParameterSpec(TAG_BITS, nonce12));
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    /**
     * @throws AEADBadTagException se a tag de autenticação não bater (adulteração/chave errada).
     */
    public static byte[] decrypt(byte[] key16, byte[] nonce12, byte[] ciphertextAndTag, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key16, "AES"), new GCMParameterSpec(TAG_BITS, nonce12));
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(ciphertextAndTag);
    }
}
