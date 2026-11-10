package mensageria.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Certificado do servidor (server.crt, DER) pinado localmente pelo cliente, fora do canal
 * inseguro, conforme "Assinatura RSA (autenticação do servidor)". O cliente confia apenas no
 * certificado idêntico, byte a byte, ao arquivo pinado — não em qualquer certificado autoassinado
 * que o servidor venha a apresentar.
 */
public final class PinnedServerCert {
    private final byte[] der;
    private final X509Certificate certificate;

    private PinnedServerCert(byte[] der, X509Certificate certificate) {
        this.der = der;
        this.certificate = certificate;
    }

    public static PinnedServerCert loadFromFile(String path) throws IOException, CertificateException {
        byte[] der = Files.readAllBytes(Path.of(path));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        return new PinnedServerCert(der, cert);
    }

    public boolean matches(byte[] presentedDer) {
        return Arrays.equals(der, presentedDer);
    }

    public PublicKey publicKey() {
        return certificate.getPublicKey();
    }

    public byte[] publicKeyEncoded() {
        return certificate.getPublicKey().getEncoded();
    }
}
