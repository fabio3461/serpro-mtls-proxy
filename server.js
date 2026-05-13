import express from "express";
import { Agent, fetch as undiciFetch } from "undici";
import fs from "node:fs";
import forge from "node-forge";
import jwt from "jsonwebtoken";

const PORT = process.env.PORT || 10000;
const SHARED_SECRET = process.env.SHARED_SECRET;
const PFX_PASSWORD = process.env.PFX_PASSWORD || "";
const SERPRO_BASE = "https://gateway.apiserpro.serpro.gov.br";

function loadPfx() {
  const paths = ["/etc/secrets/cert.pfx.b64", "/etc/secrets/cert.pfx"];
  for (const p of paths) {
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p);
      if (p.endsWith(".b64")) {
        return Buffer.from(raw.toString("utf8").replace(/\s+/g, ""), "base64");
      }
      return raw;
    }
  }
  if (process.env.PFX_BASE64) {
    return Buffer.from(process.env.PFX_BASE64.replace(/\s+/g, ""), "base64");
  }
  throw new Error("Certificado PFX não encontrado");
}

function extractKeyAndCert(pfxBuf, password) {
  const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(pfxBuf.toString("binary")));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  let privateKeyPem = null;
  let certDerB64 = null;
  for (const sc of p12.safeContents) {
    for (const bag of sc.safeBags) {
      if (
        bag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
        bag.type === forge.pki.oids.keyBag
      ) {
        privateKeyPem = forge.pki.privateKeyToPem(bag.key);
      } else if (bag.type === forge.pki.oids.certBag && !certDerB64) {
        const der = forge.asn1.toDer(forge.pki.certificateToAsn1(bag.cert)).getBytes();
        certDerB64 = forge.util.encode64(der);
      }
    }
  }
  if (!privateKeyPem || !certDerB64) {
    throw new Error("Falha ao extrair chave/certificado do PFX");
  }
  return { privateKeyPem, certDerB64 };
}

const pfxBuffer = loadPfx();
const { privateKeyPem, certDerB64 } = extractKeyAndCert(pfxBuffer, PFX_PASSWORD);
console.log("[serpro-proxy] PFX carregado, chave e certificado extraídos");

const dispatcher = new Agent({
  connect: { pfx: pfxBuffer, passphrase: PFX_PASSWORD },
});

function buildJwtToken() {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iat: now, exp: now + 300, jti: `${now}-${Math.random().toString(36).slice(2)}` },
    privateKeyPem,
    {
      algorithm: "RS256",
      header: { alg: "RS256", typ: "JWT", x5c: [certDerB64] },
    }
  );
}

const app = express();
app.use(express.raw({ type: "*/*", limit: "10mb" }));

app.get("/", (_req, res) => res.json({ ok: true, service: "serpro-mtls-proxy", version: "2.0.0" }));
app.get("/health", (_req, res) => res.json({ ok: true }));

app.all("/serpro/*", async (req, res) => {
  if (req.headers["x-shared-secret"] !== SHARED_SECRET) {
    return res.status(401).json({ error: "invalid shared secret" });
  }
  const path = req.url.replace(/^\/serpro/, "");
  const url = `${SERPRO_BASE}${path}`;

  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const kl = k.toLowerCase();
    if (["host", "x-shared-secret", "content-length", "connection", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip"].includes(kl)) continue;
    headers[k] = v;
  }
  if (!path.startsWith("/token")) {
    headers["jwt_token"] = buildJwtToken();
  }

  try {
    const upstream = await undiciFetch(url, {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
      dispatcher,
    });
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.status(upstream.status);
    upstream.headers.forEach((v, k) => {
      const kl = k.toLowerCase();
      if (!["transfer-encoding", "content-encoding", "connection"].includes(kl)) {
        res.setHeader(k, v);
      }
    });
    res.send(buf);
  } catch (err) {
    console.error("[serpro-proxy] erro:", err);
    res.status(502).json({ error: String(err?.message || err) });
  }
});

app.listen(PORT, () => console.log(`[serpro-proxy] ouvindo na porta ${PORT}`));
