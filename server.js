import cors from "cors";
import express from "express";

const app = express();

const allowedOrigins = [
  "https://www.si135.com",
  "https://si135.com",
  "http://localhost:3000",
  "http://localhost:5173",
];

app.use(cors({
  origin: function (origin, cb) {
    // อนุญาต requests ที่ไม่มี origin (เช่น curl/postman) ด้วย
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
  methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// ✅ สำคัญ: ให้ OPTIONS ผ่าน (preflight)
app.options("*", cors());

app.use(express.json());

// ... routes ของคุณตามมา
app.post("/api/auth/google", (req,res)=>{ /*...*/ })
