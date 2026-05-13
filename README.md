# SERPRO mTLS Proxy

Proxy minimalista que encaminha chamadas para a API SERPRO Integra Contador
usando certificado A1 e-CNPJ (mTLS).

## Variaveis de ambiente

- PFX_PATH (default /etc/secrets/cert.pfx) - caminho do certificado
- PFX_PASSWORD - senha do .pfx
- SHARED_SECRET - segredo compartilhado entre o app e o proxy
- PORT (default 10000)

## Endpoints

- GET /health
- ANY /serpro/<path> -> https://gateway.apiserpro.serpro.gov.br/<path>
  Exige header x-shared-secret = SHARED_SECRET
