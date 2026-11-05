const express = require("express");
const https = require("https");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const PASHA_MERCHANT_URL = "https://ecomm.pashabank.az:18443/ecomm2/MerchantHandler";
const PASHA_CLIENT_URL = "https://ecomm.pashabank.az:8463/ecomm2/ClientHandler";
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || "";

function formatPem(raw, header, footer) {
  if (!raw) return "";
  let clean = raw.replace(header, "").replace(footer, "").replace(/\s+/g, "");
  const chunks = [];
  for (let i = 0; i < clean.length; i += 64) {
    chunks.push(clean.slice(i, i + 64));
  }
  return `${header}\n${chunks.join("\n")}\n${footer}\n`;
}

function getSslCredentials() {
  const cert = formatPem(process.env.PASHA_PUBLIC_CERT, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
  const key = formatPem(process.env.PASHA_PRIVATE_KEY, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
  const ca = formatPem(process.env.PASHA_ROOT_CA, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
  return { cert, key, ca };
}

function sendPashaCommand(postParams) {
  return new Promise((resolve, reject) => {
    const { cert, key, ca } = getSslCredentials();
    if (!cert || !key) {
      return reject(new Error("Bridge mTLS cert or key is missing"));
    }

    const body = new URLSearchParams(postParams).toString();
    const req = https.request(PASHA_MERCHANT_URL, {
      method: "POST",
      cert,
      key,
      ca,
      checkServerIdentity: () => undefined,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
      },
    }, (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, raw: data.trim() });
      });
    });

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// Health check
app.get("/", (req, res) => {
  res.json({ ok: true, service: "birbazar-pasha-bridge", time: new Date().toISOString() });
});

// Auth middleware for bridge protection
function verifySecret(req, res, next) {
  if (!BRIDGE_SECRET) return next();
  const token = req.headers["x-bridge-secret"] || req.query.secret;
  if (token !== BRIDGE_SECRET) {
    return res.status(401).json({ error: "Unauthorized bridge access" });
  }
  next();
}

// 1. Command V: Register SMS 3DS transaction
app.post("/register-payment", verifySecret, async (req, res) => {
  try {
    const { amount, client_ip_addr, description = "BirBazar Payment" } = req.body;
    if (!amount) {
      return res.status(400).json({ error: "Missing amount (in gepik)" });
    }

    const params = {
      command: "v",
      amount: String(amount),
      currency: "944", // AZN
      client_ip_addr: client_ip_addr || "185.11.11.11",
      description: description.substring(0, 50),
      msg_type: "SMS",
    };

    const response = await sendPashaCommand(params);
    const text = response.raw;

    // Output is like: TRANSACTION_ID: 60ibSLUnMSQVVAMqim50qf1SKNg=
    const match = text.match(/TRANSACTION_ID:\s*([^\s]+)/i);
    if (!match) {
      return res.status(400).json({ error: "Bank rejected", raw: text });
    }

    const transactionId = match[1];
    const paymentUrl = `${PASHA_CLIENT_URL}?trans_id=${encodeURIComponent(transactionId)}`;

    res.json({
      success: true,
      transactionId,
      paymentUrl,
    });
  } catch (err) {
    console.error("Register payment error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 2. Command C: Check transaction status
app.post("/check-status", verifySecret, async (req, res) => {
  try {
    const { trans_id, client_ip_addr } = req.body;
    if (!trans_id) {
      return res.status(400).json({ error: "Missing trans_id" });
    }

    const params = {
      command: "c",
      trans_id,
      client_ip_addr: client_ip_addr || "185.11.11.11",
    };

    const response = await sendPashaCommand(params);
    res.json({
      statusCode: response.statusCode,
      raw: response.raw,
    });
  } catch (err) {
    console.error("Check status error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Pasha Bank bridge listening on port ${PORT}`);
});
