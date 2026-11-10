package mensageria.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Carrega o par de chaves RSA do servidor e seu certificado autoassinado a partir de um
 * keystore PKCS12 (gerado previamente com keytool — ver setup/generate-server-cert.ps1).
 */
public final class ServerIdentity {
    private final PrivateKey privateKey;
    private final X509Certificate certificate;
    private final byte[] certDer;

    private ServerIdentity(PrivateKey privateKey, X509Certificate certificate) throws CertificateException {
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.certDer = certificate.getEncoded();
    }

    public static ServerIdentity load(String keystorePath, char[] password, String alias) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password);
        }
        PrivateKey sk = (PrivateKey) ks.getKey(alias, password);
        if (sk == null) {
            throw new IllegalArgumentException("alias '" + alias + "' não encontrado ou sem chave privada em " + keystorePath);
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("certificado para alias '" + alias + "' não encontrado em " + keystorePath);
        }
        return new ServerIdentity(sk, cert);
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    /** server.crt em DER — enviado ao cliente a cada handshake e comparado ao arquivo pinado. */
    public byte[] certDer() {
        return certDer;
    }

    /** pk_server em bytes raw (SubjectPublicKeyInfo DER), usado no hash H assinado no handshake. */
    public byte[] publicKeyEncoded() {
        return certificate.getPublicKey().getEncoded();
    }
}
