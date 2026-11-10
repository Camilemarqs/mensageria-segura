package mensageria.common;

/**
 * Constantes do protocolo: tipos de frame e tamanhos de campo.
 */
public final class Protocol {
    private Protocol() {}

    // Tipos de frame (primeiro byte do payload, após o prefixo de tamanho)
    public static final byte CLIENT_HELLO = 0x01; // C -> S: client_id + pk_client
    public static final byte SERVER_HELLO = 0x02; // S -> C: cert + assinatura + salt_srv
    public static final byte PEER_ADD     = 0x03; // S -> C: seq_no + client_id + pk_client de um peer
    public static final byte PEER_REMOVE  = 0x04; // S -> C: seq_no + client_id de um peer desconectado
    public static final byte E2E_FRAME    = 0x05; // C -> S -> C: frame E2E cifrado (relay puro)
    public static final byte ERROR_MSG    = 0x06; // S -> C: seq_no + code + mensagem

    public static final int CLIENT_ID_LEN   = 16; // UUID v4 binário
    public static final int X25519_PUB_LEN  = 32; // chave pública X25519 raw
    public static final int SALT_LEN        = 16; // salt_srv
    public static final int NONCE_LEN       = 12; // IV_base (4B) || seq_no (8B)
    public static final int IV_BASE_LEN     = 4;
    public static final int SEQ_LEN         = 8;
    public static final int GCM_TAG_LEN     = 16;
    public static final int MAX_PLAINTEXT   = 4096;

    // Tamanho máximo de frame aceito pelo framing (evita DoS por tamanho inválido/absurdo).
    // Cabe o maior E2E_FRAME possível (nonce+ids+seq+plaintext+tag) com folga, além de
    // mensagens de handshake contendo o certificado RSA.
    public static final int MAX_FRAME_LEN = 64 * 1024;
}
