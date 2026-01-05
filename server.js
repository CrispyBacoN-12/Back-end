import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: ["https://www.si135.com", "https://si135.com", "http://localhost:3000"],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.options("*", cors());

app.get("/health", (req, res) => res.status(200).send("ok"));

// ✅ เปลี่ยนเป็นหลาย client id
const GOOGLE_CLIENT_IDS = (process.env.GOOGLE_CLIENT_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const JWT_SECRET = process.env.JWT_SECRET;
const allowedDomain = (process.env.ALLOWED_EMAIL_DOMAIN || "student.mahidol.edu").toLowerCase();

if (!GOOGLE_CLIENT_IDS.length) {
  console.error("Missing GOOGLE_CLIENT_IDS env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET env");
  process.exit(1);
}

// helper: verify กับทุก client id จนกว่าจะผ่าน
async function verifyWithAnyAudience(idToken) {
  for (const clientId of GOOGLE_CLIENT_IDS) {
    try {
      const client = new OAuth2Client(clientId);
      const ticket = await client.verifyIdToken({
        idToken,
        audience: clientId,
      });
      const payload = ticket.getPayload();
      if (payload) return payload;
    } catch {
      // ไม่ผ่านตัวนี้ ลองตัวถัดไป
    }
  }
  return null;
}

app.post("/api/auth/google", async (req, res) => {
  try {
    const { id_token } = req.body;
    if (!id_token) return res.status(400).json({ error: "Missing id_token" });

    const payload = await verifyWithAnyAudience(id_token);
    if (!payload) return res.status(401).json({ error: "Invalid Google token" });

    const email = payload.email || "";
    const emailVerified = payload.email_verified;

    // ✅ แนะนำ: บังคับ email ต้อง verified
    if (!email || !emailVerified) {
      return res.status(401).json({ error: "Email not verified" });
    }

    // 🔒 จำกัดโดเมน mahidol
    const domain = email.split("@").pop()?.toLowerCase();
    if (domain !== allowedDomain) {
      return res.status(403).json({ error: `University email only (@${allowedDomain})` });
    }

    const token = jwt.sign(
      { email, sub: payload.sub },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({ token, email });
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).json({ error: "Invalid Google token" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
