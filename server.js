    const express = require('express');
    const cors = require('cors');
    const { OAuth2Client } = require('google-auth-library'); 
    const jwt = require('jsonwebtoken'); // 👈 เพิ่มการนำเข้า JWT
    require('dotenv').config(); 

    const app = express();
    app.use(express.json()); 

    const allowedOrigin = process.env.NODE_ENV === 'production' 
        ? 'https://yourdomain.com' 
        : ['http://localhost:5173', 'http://localhost:5174'];
    // 🚨 แก้ไข: เปิดใช้ CORS ด้วย allowedOrigin ที่กำหนดไว้
    app.use(cors({ origin: allowedOrigin }));

    const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    // 🚨 กำหนด Secret Key สำหรับ JWT (ต้องโหลดจาก .env)
    const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_UNSAFE_DEFAULT_SECRET'; 
    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        // คาดหวัง Header เป็น: 'Authorization': 'Bearer TOKEN'
        const token = authHeader && authHeader.split(' ')[1]; 

        if (token == null) return res.sendStatus(401); // 401: Unauthorized (ไม่มี Token)

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.sendStatus(403); // 403: Forbidden (Token ไม่ถูกต้อง/หมดอายุ)
            req.user = user; // เก็บข้อมูลผู้ใช้ที่ถอดรหัสแล้วใน Request
            next();
        });
    };

    // 🚨 สร้าง Endpoint ใหม่สำหรับดึงข้อมูลส่วนตัว (แก้ปัญหา 404)
    app.get('/api/user/profile', authenticateToken, (req, res) => {
        // req.user มีข้อมูล id, email, name ที่เราใส่ไว้ใน JWT
        
        res.json({
            message: "Profile data retrieved successfully.",
            greeting: `คุณ ${req.user.name}`,
            name: req.user.name,
            email: req.user.email,
        });
    });
    const client = new OAuth2Client(CLIENT_ID); 

    // Endpoint สำหรับการรับและตรวจสอบ ID Token
    app.post('/api/auth/google', async (req, res) => {
        // 1. รับ ID Token จาก Body
        const { token } = req.body; 

        console.log("Secret loaded:", process.env.GOOGLE_CLIENT_SECRET ? "YES" : "NO");

        if (!token) {
            return res.status(400).send({ error: 'Token is required' });
        }

        try {
            // 2. ตรวจสอบ Token กับ Google
            const ticket = await client.verifyIdToken({
                idToken: token,
                audience: CLIENT_ID, 
            });
            
            // 3. ดึงข้อมูลผู้ใช้ที่ตรวจสอบแล้ว (Payload)
            const payload = ticket.getPayload();
            const { email, name, picture, hd } = payload; 
            
            console.log("--- DEBUG ---");
            console.log("Email from Token:", email);
            console.log("Hosted Domain (hd) from Google:", hd);
            console.log("--- DEBUG ---");

            // 4. *** การตรวจสอบโดเมนมหาวิทยาลัย (สำคัญ) ***
            const requiredDomain = 'student.mahidol.edu';
            if (hd !== requiredDomain) {
                console.warn(`Attempted login from non-required domain: ${email} (HD: ${hd})`);
                return res.status(401).send({ error: 'Login requires a valid university email address.' });
            }
            
            // 5. ✅ สร้าง JWT/Session Token ของระบบเราเอง (แทนที่ [TODO])
            const userPayload = { 
                id: email, // ใช้ email เป็น ID ชั่วคราว
                email: email,
                name: name
            };
            const serverToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1d' }); 
            
            // 6. ส่ง Response สำเร็จกลับไปให้ Front-end
            res.status(200).json({ 
                message: "Login successful and verified", 
                email,
                name,
                authToken: serverToken // 👈 ส่ง Token ของระบบเรากลับไป
            });
                

        } catch (error) {
            console.error("Verification failed:", error.message);
            res.status(401).send({ error: 'Invalid or expired ID Token.' });
        }
    });

    // ... (ส่วนที่เหลือของไฟล์)
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`🚀 Authentication Server running on port ${PORT}`);
        console.log(`Client ID: ${CLIENT_ID ? 'configured' : 'NOT CONFIGURED'}`);
    });