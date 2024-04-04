const express = require('express');
const { status } = require('express/lib/response');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'event2go-login'

const app = express();
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/evant2go', { useNewUrlParser: true, useUnifiedTopology: true });

const UsersSchema = new mongoose.Schema({
    name: String,
    age: Number,
    email: String,
    password: String, 
});

const UserModel = mongoose.model("users", UsersSchema);

app.get("/getUsers", async (req, res, next) => {
    try {
        const users = await UserModel.find();
        res.json(users);
    } catch (err) {
        next(err);
    }
});

//Register//
app.post('/Register', validateUserData, async (req, res, next) => {
    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Create new user with hashed password
        const newUser = await UserModel.create({
            name: req.body.name,
            age: req.body.age,
            email: req.body.email,
            password: hashedPassword
        });

        res.json({ status: 'ok', newUser });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

function validateUserData(req, res, next) {
    const requiredFields = ['name', 'age', 'email', 'password'];
    const missingFields = [];

    requiredFields.forEach(field => {
        if (!(field in req.body)) {
            missingFields.push(field);
        }
    });

    if (missingFields.length > 0) {
        return res.status(400).json({ status: 'error', message: `Missing fields: ${missingFields.join(', ')}` });
    }

    // Additional validation logic for each field can be added here

    next();
}
//Login//
app.post("/login", async (req, res, next) => {
    const { email, password } = req.body;

    try {
        // ค้นหาผู้ใช้โดยใช้อีเมล์ที่ระบุ
        const user = await UserModel.findOne({ email });

        // ถ้าไม่พบผู้ใช้ ส่งข้อความข้อผิดพลาดกลับไป
        if (!user) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        // ตรวจสอบรหัสผ่าน
        const passwordMatch = await bcrypt.compare(password, user.password);

        // ถ้ารหัสผ่านไม่ตรงกัน ส่งข้อความข้อผิดพลาดกลับไป
        if (!passwordMatch) {
            return res.status(401).json({ status: 'error', message: 'Incorrect password' });
        }

        // ถ้ารหัสผ่านถูกต้อง สร้าง JSON Web Token (JWT)
        const token = jwt.sign({ email: user.email }, secret, { expiresIn: '1h' });

        // ส่งข้อความสำเร็จพร้อมกับ token กลับไป
        res.json({ status: 'ok', message: 'Login successful', token });
    } catch (err) {
        // ถ้าเกิดข้อผิดพลาดขึ้น ส่งข้อความข้อผิดพลาดกลับไป
        res.status(500).json({ status: 'error', message: err.message });
    }
});

//authen//
app.post("/authen", async (req, res, next) => {
    try {
        // ดึง token จาก header Authorization
        const authHeader = req.headers.authorization;
        
        // ตรวจสอบว่ามี token หรือไม่
        if (!authHeader) {
            return res.status(401).json({ status: 'error', message: 'Token is missing' });
        }

        // แยก token ออกมาจาก header
        const token = authHeader.split(' ')[1];

        // ตรวจสอบ token และถอดรหัส
        const decoded = jwt.verify(token, secret);

        // ส่งข้อมูลที่ถอดรหัสได้กลับไป
        res.json({ status: 'ok', decoded });
    } catch (err) {
        // ถ้าเกิดข้อผิดพลาดในการตรวจสอบหรือถอดรหัส token
        res.status(500).json({ status: 'error', message: err.message });
    }
});

///
app.delete("/deleteUser/:id", async (req, res, next) => {
    try {
        const userId = req.params.id;
        
        // ค้นหาและลบผู้ใช้จากฐานข้อมูลด้วย id
        const deletedUser = await UserModel.findByIdAndDelete(userId);
        
        // ตรวจสอบว่ามีผู้ใช้ที่ถูกลบหรือไม่
        if (!deletedUser) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }
        
        res.json({ status: 'ok', message: 'User deleted successfully' });
    } catch (err) {
        next(err);
    }
});
////////////////////////////////////////
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message });
});

app.listen(3322, () => {
    console.log("Server is Running");
});
