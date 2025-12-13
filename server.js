import cors from "cors";
import express from "express";

const app = express();

app.use(express.json());

app.use(cors({
  origin: ["https://www.si135.com", "https://si135.com"],
  methods: ["GET","POST","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// ให้ OPTIONS ผ่านทุก path
app.options("*", cors());

// routes
app.post("/api/auth/google", ...);
