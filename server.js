// Proxy mTLS SERPRO - encaminha chamadas do app Lovable para a API SERPRO
// usando o certificado A1 e-CNPJ do escritorio.
import express from "express";
import fs from "node:fs";
import { Agent, fetch as undiciFetch } from "undici";

const PORT = process.env.PORT || 10000;
const SHARED_SECRET = process.env.SHARED_SECRET;
const PFX_PASSWORD = process.env.PFX_PASSWORD;
const SERPRO_BASE = "https://gateway.apiserpro.serpro.gov.br";

if (!SHARED_SECRET) { console.error("SHARED_SECRET nao configurado"); process.exit(1); }
if (!PFX_PASSWORD) { console.error("PFX_PASSWORD nao configurado"); process.exit(1); }

// Carrega o .pfx de uma das fontes (ordem de prioridade):
// 1. /etc/secrets/cert.pfx.b64  (Secret File em base64 - recomendado no Render)
// 2. /etc/secrets/cert.pfx      (Secret File binario)
// 3. process.env.PFX_BASE64     (variavel de ambiente em base64)
function loadPfx() {
  const b64Path = "/etc/secrets/cert.pfx.b64";
  const binPath = "/etc/secrets/cert.pfx";
  if (fs.existsSync(b64Path)) {
    const text = fs.readFileSync(b64Path, "utf8").replace(/\s+/g, "");
    return Buffer.from(text, "base64");
  }
  if (fs.existsSync(binPath)) {
    return fs.readFileSync(binPath);
  }
  if (process.env.PFX_BASE64) {
    return Buffer.from(process.env.PFX_BASE64.replace(/\s+/g, ""), "base64");
  }
  console.error("Certificado nao encontrado. Adicione /etc/secrets/cert.pfx.b64 (Secret File em base64) ou variavel PFX_BASE64.");
  process.exit(1);
}

const pfx = loadPfx();
const dispatcher = new Agent({ connect: { pfx: [{ buf: pfx, passphrase: PFX_PASSWORD }] } });

const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(express.text({ type: ["text/*", "application/x-www-form-urlencoded"], limit: "5mb" }));

app.get("/", (_req, res) => res.json({ ok: true, service: "serpro-mtls-proxy" }));
app.get("/health", (_req, res) => res.json({ ok: true }));

app.all("/serpro/*", async (req, res) => {
  if (req.header("x-shared-secret") !== SHARED_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const subPath = req.path.replace(/^\/serpro/, "");
  const qIdx = req.originalUrl.indexOf("?");
  const qs = qIdx >= 0 ? req.originalUrl.slice(qIdx) : "";
  const url = SERPRO_BASE + subPath + qs;
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (["host","connection","content-length","x-shared-secret"].includes(k.toLowerCase())) continue;
    headers[k] = v;
  }
  let body;
  if (req.method !== "GET" && req.method !== "HEAD") {
    body = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {});
  }
  try {
    const upstream = await undiciFetch(url, { method: req.method, headers, body, dispatcher });
    const buf = Buffer.from(await upstream.arrayBuffer());
    upstream.headers.forEach((value, key) => {
      if (["content-encoding","transfer-encoding","content-length"].includes(key.toLowerCase())) return;
      res.setHeader(key, value);
    });
    res.status(upstream.status).send(buf);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(502).json({ error: "proxy_failed", message: String(err?.message || err) });
  }
});

app.listen(PORT, () => console.log("SERPRO mTLS proxy ouvindo em :" + PORT));
