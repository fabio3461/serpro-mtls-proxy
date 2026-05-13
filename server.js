// server.js — SERPRO mTLS proxy (Integra Contador) v3.0.0
const https = require("https");
const express = require("express");
const morgan = require("morgan");
const forge = require("node-forge");
const fetch = require("node-fetch");

const PORT = process.env.PORT || 10000;
const SHARED_SECRET = process.env.SHARED_SECRET;
const PFX_BASE64 = process.env.PFX_BASE64;
const PFX_PASSWORD = process.env.PFX_PASSWORD || "";

if (!SHARED_SECRET) { console.error("SHARED_SECRET ausente"); process.exit(1); }
if (!PFX_BASE64)    { console.error("PFX_BASE64 ausente");    process.exit(1); }

// Extrai chave + certificado do PFX (PEM)
const pfxDer = Buffer.from(PFX_BASE64, "base64");
const p12Asn1 = forge.asn1.fromDer(pfxDer.toString("binary"));
const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, PFX_PASSWORD);
let keyPem = "";
let certPem = "";
for (const sc of p12.safeContents) {
  for (const sb of sc.safeBags) {
    if (sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) {
      keyPem = forge.pki.privateKeyToPem(sb.key);
    } else if (sb.type === forge.pki.oids.certBag) {
      certPem += forge.pki.certificateToPem(sb.cert);
    }
  }
}
console.log("[serpro-proxy] PFX carregado, chave e certificado extraidos");

const mtlsAgent = new https.Agent({ key: keyPem, cert: certPem, keepAlive: true });

const app = express();
app.use(morgan("tiny"));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.text({ type: "*/*", limit: "2mb" }));

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  if (req.headers["x-shared-secret"] !== SHARED_SECRET) {
    return res.status(401).json({ error: "invalid shared secret" });
  }
  next();
});

app.get("/health", (_req, res) => res.json({ ok: true, version: "3.0.0" }));

// AUTENTICACAO — endpoint correto que devolve access_token + jwt_token
app.post("/serpro/token", async (req, res) => {
  try {
    const auth = req.headers["authorization"];
    if (!auth) return res.status(400).json({ error: "missing Authorization Basic" });
    const r = await fetch("https://autenticacao.sapi.serpro.gov.br/authenticate", {
      method: "POST",
      headers: {
        Authorization: auth,
        "Role-Type": "TERCEIROS",
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: "grant_type=client_credentials",
      agent: mtlsAgent,
    });
    const text = await r.text();
    res.status(r.status).type(r.headers.get("content-type") || "application/json").send(text);
  } catch (e) {
    res.status(500).json({ error: String(e && e.message || e) });
  }
});

// CHAMADAS Integra Contador (Consultar / Emitir / Declarar / Apoiar / Monitorar)
app.post("/serpro/integra-contador/v1/:op", async (req, res) => {
  try {
    const op = req.params.op;
    const bearer = req.headers["authorization"];
    const jwt = req.headers["jwt_token"];
    if (!bearer) return res.status(400).json({ error: "missing Authorization Bearer" });
    if (!jwt)    return res.status(400).json({ error: "missing jwt_token header" });

    const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    const r = await fetch(`https://gateway.apiserpro.serpro.gov.br/integra-contador/v1/${op}`, {
      method: "POST",
      headers: {
        Authorization: bearer,
        jwt_token: jwt,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body,
      agent: mtlsAgent,
    });
    const text = await r.text();
    res.status(r.status).type(r.headers.get("content-type") || "application/json").send(text);
  } catch (e) {
    res.status(500).json({ error: String(e && e.message || e) });
  }
});

app.listen(PORT, () => console.log(`[serpro-proxy] ouvindo na porta ${PORT}`));
