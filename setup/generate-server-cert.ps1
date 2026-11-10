# Gera o par de chaves RSA do servidor e seu certificado autoassinado, usados no handshake
# (RSA-PSS sobre ECDHE) descrito no Trabalho Pratico 3.
#
# Saidas (na raiz do projeto):
#   server.p12  - keystore PKCS12 com a chave privada RSA + certificado (uso do SERVIDOR)
#   server.crt  - certificado em DER, para ser "pinado" nos CLIENTES (fora do canal inseguro)
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File setup\generate-server-cert.ps1

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$keystore = Join-Path $root "server.p12"
$certOut  = Join-Path $root "server.crt"
$alias    = "server"
$storePass = "changeit"

if (Test-Path $keystore) { Remove-Item $keystore -Force }
if (Test-Path $certOut)  { Remove-Item $certOut -Force }

keytool -genkeypair `
  -alias $alias `
  -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 3650 `
  -keystore $keystore -storetype PKCS12 `
  -storepass $storePass -keypass $storePass `
  -dname "CN=MensageriaServer, OU=TP3, O=SegurancaDaInformacao, C=BR"

keytool -exportcert -alias $alias -keystore $keystore -storepass $storePass -file $certOut

Write-Host ""
Write-Host "OK: $keystore (mantenha no servidor, NUNCA distribua)"
Write-Host "OK: $certOut  (copie para cada cliente - e o certificado pinado)"
