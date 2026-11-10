# Mensageria Segura Multi-Cliente (Trabalho Prático 2)

Implementação em Java (JDK padrão, sem dependências externas) de mensageria ponta-a-ponta:
handshake autenticado (RSA-PSS sobre certificado autoassinado), ECDHE (X25519) para sigilo
perfeito, HKDF-SHA256 para derivação de chaves e AES-128-GCM para as mensagens. O servidor
atua apenas como relay: nunca vê texto claro nem deriva as chaves simétricas E2E.

## Build

Com Maven (ou importando o `pom.xml` na IDE):

```powershell
mvn compile
```

Sem Maven instalado, compila direto com javac (não há dependências externas):

```powershell
javac -d out -encoding UTF-8 (Get-ChildItem -Recurse -Filter *.java src\main\java).FullName
```

## 1. Gerar a identidade do servidor (uma vez)

```powershell
powershell -ExecutionPolicy Bypass -File setup\generate-server-cert.ps1
```

Gera `server.p12` (fica só no servidor) e `server.crt` (copiar para cada cliente — é o
certificado "pinado" fora do canal inseguro, usado para validar a assinatura RSA-PSS do
servidor no handshake e detectar MITM).

## 2. Rodar o servidor

```powershell
java -cp out mensageria.server.Server <porta> server.p12 changeit server
# ex.: java -cp out mensageria.server.Server 9000 server.p12 changeit server
```

## 3. Rodar clientes (em terminais separados)

```powershell
java -cp out mensageria.client.Client <host> <porta> server.crt [client_id opcional]
# ex.: java -cp out mensageria.client.Client 127.0.0.1 9000 server.crt
```

Se `client_id` não for informado, um UUID v4 aleatório é gerado. Comandos no console do cliente:

```
/list               lista peers com chaves E2E já derivadas (fingerprint da pk de cada um)
/send <id> <msg>     envia mensagem cifrada E2E para o peer <id>
/all <msg>           envia a mensagem para todos os peers conhecidos
/quit                encerra a conexão
```

## 4. Testar bitflip / replay

`MitmProxy` fica entre um cliente e o servidor, corrompendo ou duplicando o N-ésimo frame
E2E na direção cliente→servidor:

```powershell
java -cp out mensageria.tools.MitmProxy 9001 127.0.0.1 9000 flipbit 1   # bitflip
java -cp out mensageria.tools.MitmProxy 9001 127.0.0.1 9000 replay 1   # replay
```

Conecte o cliente remetente na porta do proxy (`9001`) em vez da porta real do servidor
(`9000`); o destinatário continua conectado direto ao servidor.

## Decisões de projeto e simplificações documentadas

O enunciado contém alguns pontos ilustrativos/ambíguos (ele mesmo convida a documentar
simplificações). As decisões tomadas aqui:

- **`salt_srv` compartilhado por "época" do servidor**, em vez de um salt por conexão
  individual. É necessário porque dois clientes distintos (A e B) precisam chegar ao mesmo
  `PRK = HKDF-Extract(salt_srv, Z_AB)` para que `Key_A2B`/`Key_B2A` batam dos dois lados; um
  salt por-sessão impediria qualquer par de derivar a mesma chave. O salt é rotacionado sempre
  que o último cliente se desconecta (próxima "época" nunca reutiliza o salt anterior). A
  propriedade de "não reutilizar segredo anterior" em reconexões continua garantida pelas
  chaves ECDHE efêmeras, sempre recriadas a cada conexão (ver `Server.java`, campo
  `currentSalt`).
- **Reconstrução do nonce**: o nonce de 12 bytes trafega explícito no frame (`[nonce][sender_id]
  [recipient_id][seq_no][ciphertext+tag]`), mas o destinatário nunca confia cegamente nele.
  No primeiro frame de um peer, o `IV_base` (4 primeiros bytes) é fixado por *trust-on-first-use*
  da sessão; em todo frame seguinte, o destinatário reconstrói `nonce = IV_base_recv || seq_no`
  e exige que bata byte a byte com o nonce recebido, além de exigir `seq_no` estritamente maior
  que o último aceito (anti-replay) — ver `Client.handleE2eFrame`.
- **Mensagens de controle do servidor** (`PEER_ADD`/`PEER_REMOVE`/`ERROR_MSG`) carregam o
  contador `seq_no` descrito na tabela `sessions`, mas não são cifradas: não há segredo
  simétrico servidor↔cliente nesse canal (o RSA do servidor é usado só para assinar o
  handshake). A integridade desse canal depende do TCP; é adequado para o escopo do trabalho,
  já que nenhum dado sensível trafega nessas mensagens.
- **Certificado "autoassinado"**: gerado com `keytool` (ver `setup/`) e pinado pelo cliente por
  comparação **byte a byte** do DER recebido no handshake contra o arquivo `server.crt` local —
  qualquer divergência aborta a conexão antes mesmo de verificar a assinatura.
