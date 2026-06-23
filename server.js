// server.js — SERPRO mTLS proxy (Integra Contador) v3.2.0
const https = require("https");
const express = require("express");
const morgan = require("morgan");
const fetch = require("node-fetch");

const PORT = process.env.PORT || 10000;
const SHARED_SECRET = process.env.SHARED_SECRET;
const PFX_BASE64 = process.env.PFX_BASE64;
const PFX_PASSWORD = process.env.PFX_PASSWORD || "";
const ADN_BRIDGE_SECRET = process.env.ADN_BRIDGE_SECRET;

function requiredEnv(name, value) {
  if (!value) {
    console.error(`[serpro-proxy] ERRO: variavel de ambiente ausente: ${name}`);
    console.error(`[serpro-proxy] Configure ${name} no Render em Environment.`);
    process.exit(1);
  }
}

requiredEnv("SHARED_SECRET", SHARED_SECRET);
requiredEnv("PFX_BASE64", PFX_BASE64);

let mtlsAgent;
try {
  const pfxBuffer = Buffer.from(PFX_BASE64.replace(/\s/g, ""), "base64");

  if (!pfxBuffer.length) {
    throw new Error("PFX_BASE64 vazio ou invalido");
  }

  mtlsAgent = new https.Agent({
    pfx: pfxBuffer,
    passphrase: PFX_PASSWORD,
    keepAlive: true,
  });

  console.log(`[serpro-proxy] Certificado PFX carregado (${pfxBuffer.length} bytes)`);
} catch (error) {
  console.error("[serpro-proxy] ERRO ao carregar o certificado PFX:");
  console.error(error && error.stack ? error.stack : String(error));
  console.error("[serpro-proxy] Confira PFX_BASE64 e PFX_PASSWORD no Render.");
  process.exit(1);
}

const app = express();
app.use(morgan("tiny"));
app.use(express.json({ limit: "5mb", type: ["application/json", "application/*+json"] }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.text({ type: "text/*", limit: "2mb" }));

function sendJson(res, status, data) {
  return res.status(status).type("application/json").send(JSON.stringify(data));
}

function getHeader(req, name) {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  if (req.path === "/v1/adn-nfse") return next(); // ADN usa header proprio (x-adn-secret)

  const sharedSecret = getHeader(req, "x-shared-secret");
  if (sharedSecret !== SHARED_SECRET) {
    return sendJson(res, 401, { error: "invalid shared secret" });
  }

  return next();
});

app.get("/health", (_req, res) => {
  return sendJson(res, 200, { ok: true, version: "3.2.0" });
});

app.post("/serpro/token", async (req, res) => {
  try {
    const authorization = getHeader(req, "authorization");

    if (!authorization || !authorization.startsWith("Basic ")) {
      return sendJson(res, 400, { error: "missing Authorization Basic" });
    }

    const response = await fetch("https://autenticacao.sapi.serpro.gov.br/authenticate", {
      method: "POST",
      headers: {
        Authorization: authorization,
        "Role-Type": "TERCEIROS",
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: "grant_type=client_credentials",
      agent: mtlsAgent,
    });

    const text = await response.text();
    return res
      .status(response.status)
      .type(response.headers.get("content-type") || "application/json")
      .send(text);
  } catch (error) {
    console.error("[serpro-proxy] ERRO /serpro/token:", error && error.stack ? error.stack : String(error));
    return sendJson(res, 500, { error: String((error && error.message) || error) });
  }
});

app.post("/serpro/integra-contador/v1/:op", async (req, res) => {
  try {
    const op = req.params.op;
    const authorization = getHeader(req, "authorization");
    const jwtToken = getHeader(req, "jwt_token");

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return sendJson(res, 400, { error: "missing Authorization Bearer" });
    }

    if (!jwtToken) {
      return sendJson(res, 400, { error: "missing jwt_token header" });
    }

    const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});

    const response = await fetch(`https://gateway.apiserpro.serpro.gov.br/integra-contador/v1/${op}`, {
      method: "POST",
      headers: {
        Authorization: authorization,
        jwt_token: jwtToken,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body,
      agent: mtlsAgent,
    });

    const text = await response.text();
    return res
      .status(response.status)
      .type(response.headers.get("content-type") || "application/json")
      .send(text);
  } catch (error) {
    console.error("[serpro-proxy] ERRO /serpro/integra-contador:", error && error.stack ? error.stack : String(error));
    return sendJson(res, 500, { error: String((error && error.message) || error) });
  }
});

// ===== ADN NFS-e Nacional (PFX por empresa, vem na requisicao) =====
app.post("/v1/adn-nfse", async (req, res) => {
  try {
    if (!ADN_BRIDGE_SECRET) {
      return sendJson(res, 500, { ok: false, error: "ADN_BRIDGE_SECRET ausente no proxy" });
    }
    const adnSecret = getHeader(req, "x-adn-secret");
    if (adnSecret !== ADN_BRIDGE_SECRET) {
      return sendJson(res, 401, { ok: false, error: "invalid_adn_secret" });
    }

    const { cnpj, pfx_base64, password, data_inicial, data_final, pagina = 1 } = req.body || {};
    if (!cnpj || !pfx_base64 || !password || !data_inicial || !data_final) {
      return sendJson(res, 400, { ok: false, error: "missing_fields" });
    }

    const pfxBuf = Buffer.from(String(pfx_base64).replace(/\s/g, ""), "base64");
    const agent = new https.Agent({ pfx: pfxBuf, passphrase: password, keepAlive: false });

    const url = `https://adn.nfse.gov.br/contribuintes/${cnpj}/nfses?dataInicial=${data_inicial}&dataFinal=${data_final}&pagina=${pagina}`;
    const upstream = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      agent,
    });

    const text = await upstream.text();
    if (!upstream.ok) {
      return sendJson(res, 502, { ok: false, error: `adn_${upstream.status}: ${text.slice(0, 300)}` });
    }

    let data;
    try { data = JSON.parse(text); } catch { data = {}; }
    const xmls = (data && data.nfses ? data.nfses : []).map((n) => Buffer.from(n.xml || "").toString("base64"));
    return sendJson(res, 200, {
      ok: true,
      xmls,
      proxima_pagina: (data && data.proximaPagina) || null,
    });
  } catch (error) {
    console.error("[serpro-proxy] ERRO /v1/adn-nfse:", error && error.stack ? error.stack : String(error));
    return sendJson(res, 500, { ok: false, error: String((error && error.message) || error) });
  }
});

app.use((req, res) => {
  return sendJson(res, 404, { error: "not found" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[serpro-proxy] ouvindo na porta ${PORT}`);
  console.log("[serpro-proxy] version: 3.2.0");
});
