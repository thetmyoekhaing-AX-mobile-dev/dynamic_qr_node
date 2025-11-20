import express from "express";
import { randomBytes, createHmac } from "crypto";

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 5000;

// ----------------
// Config
// ----------------
const TOKEN_TTL = 20; // seconds
const SECRET_KEY = process.env.SECRET_KEY || "supersecretkey";

// In-memory token store
const tokens = {};

// ----------------
// Helper: generate signed token
// ----------------
function generateToken() {
  const timestamp = Date.now();
  const randomPart = randomBytes(8).toString("hex");
  const signature = createHmac("sha256", SECRET_KEY)
    .update(`${timestamp}:${randomPart}`)
    .digest("hex");

  const token = `${timestamp}:${randomPart}:${signature}`;
  tokens[token] = timestamp + TOKEN_TTL * 1000; // store expiry
  return token;
}

// ----------------
// /token → Generate QR for Flutter app
// ----------------
app.get("/token", async (req, res) => {
  try {
    const token = generateToken();

    res.send({ token });
  } catch (err) {
    console.error("QR generation error:", err);
    res.status(500).json({ error: "QR generation failed" });
  }
});

// ----------------
// /validate → Flutter app calls this
// ----------------
app.get("/validate", (req, res) => {
  const token = req.query.token;

  if (!token || !tokens[token]) {
    return res.json({ valid: false, error: "invalid token" });
  }

  // Check expiry
  if (Date.now() > tokens[token]) {
    delete tokens[token];
    return res.json({ valid: false, error: "token expired" });
  }

  // Optional: Verify signature again (extra safety)
  const parts = token.split(":");
  if (parts.length !== 3) {
    delete tokens[token];
    return res.json({ valid: false, error: "token malformed" });
  }

  const [timestamp, randomPart, signature] = parts;
  const expectedSig = createHmac("sha256", SECRET_KEY)
    .update(`${timestamp}:${randomPart}`)
    .digest("hex");

  if (signature !== expectedSig) {
    delete tokens[token];
    return res.json({ valid: false, error: "tampered" });
  }

  // One-time use → remove token
  delete tokens[token];

  res.json({ valid: true });
});

// ----------------
// Cleanup expired tokens every 10 sec
// ----------------
setInterval(() => {
  const now = Date.now();
  for (const t in tokens) {
    if (tokens[t] < now) delete tokens[t];
  }
}, 10000);

// ----------------
// Start server
// ----------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
