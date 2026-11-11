import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';

const app = express();
const JWT_SECRET = 'your_jwt_secret_key';

// ------------------------------------------
// Middleware & CORS Configuration
// ------------------------------------------
// อนุญาตให้ส่ง Cookie ข้าม Origin (localhost:5173 -> localhost:5000)
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser()); // อ่าน Cookie จาก Request

// ------------------------------------------
// Database Connection
// ------------------------------------------
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'your_mysql_password', // <--- เปลี่ยนเป็นรหัสผ่าน MySQL ของคุณ
  database: 'food_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware ตรวจสอบ JWT จาก HttpOnly Cookie
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token; // ดึง Token จาก Cookie แทน Header

  if (!token) return res.status(401).json({ message: 'กรุณาเข้าสู่ระบบก่อนใช้งาน' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    req.user = user;
    next();
  });
};

// ตัวเลือกตั้งค่า Cookie ที่ปลอดภัย
const cookieOptions = {
  httpOnly: true, // ป้องกัน JavaScript เข้าถึง Cookie (ป้องกัน XSS)
  secure: false,  // เปลี่ยนเป็น true เมื่อรันบน HTTPS ในระบบ Production
  sameSite: 'lax', // ป้องกัน CSRF
  maxAge: 24 * 60 * 60 * 1000 // อายุ 1 วัน
};

// ==========================================
// 1. AUTH API (Register, Login, Logout, Me)
// ==========================================

// สมัครสมาชิก
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }

    const [existing] = await db.query(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username.trim(), email.trim()]
    );
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Username หรือ Email นี้ถูกใช้งานแล้ว' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username.trim(), email.trim(), hashedPassword, 'member']
    );

    const user = { id: result.insertId, username: username.trim(), email: email.trim(), role: 'member' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '1d' });

    // ฝัง JWT Token ลงใน HttpOnly Cookie
    res.cookie('token', token, cookieOptions);
    res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ', user });
  } catch (err) {
    console.error('Register Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// เข้าสู่ระบบ
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'กรุณากรอก Username และ Password' });
    }

    const [users] = await db.query(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username.trim(), username.trim()]
    );
    if (users.length === 0) {
      return res.status(400).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const userData = { id: user.id, username: user.username, email: user.email, role: user.role };
    const token = jwt.sign(userData, JWT_SECRET, { expiresIn: '1d' });

    // ฝัง JWT Token ลงใน HttpOnly Cookie
    res.cookie('token', token, cookieOptions);
    res.json({ message: 'เข้าสู่ระบบสำเร็จ', user: userData });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ออกจากระบบ (ล้าง Cookie)
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', cookieOptions);
  res.json({ message: 'ออกจากระบบเรียบร้อย' });
});

// ตรวจสอบ Session ปัจจุบันจาก Cookie
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// ==========================================
// 2. RECIPES & CATEGORIES API
// ==========================================

// ดึงสูตรอาหารทั้งหมด
app.get('/api/recipes', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT r.*, c.name AS category_name FROM recipes r LEFT JOIN categories c ON r.category_id = c.id ORDER BY r.id DESC'
    );
    const recipes = rows.map((r) => {
      let imageUrl = '/images/placeholder.jpg';
      if (r.image && Buffer.isBuffer(r.image)) {
        imageUrl = `data:image/jpeg;base64,${r.image.toString('base64')}`;
      } else if (typeof r.image === 'string' && r.image.trim() !== '') {
        imageUrl = r.image;
      }
      return { ...r, image: imageUrl };
    });
    res.json(recipes);
  } catch (err) {
    console.error('Fetch Recipes Error:', err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลสูตรอาหาร' });
  }
});

// ดึงรายละเอียดสูตรอาหารทีละ 1 เมนู
app.get('/api/recipes/:id', async (req, res) => {
  try {
    const recipeId = req.params.id;
    const [recipes] = await db.query(
      'SELECT r.*, c.name AS category_name FROM recipes r LEFT JOIN categories c ON r.category_id = c.id WHERE r.id = ?',
      [recipeId]
    );

    if (recipes.length === 0) {
      return res.status(404).json({ message: 'ไม่พบสูตรอาหารที่ต้องการ' });
    }

    const recipe = recipes[0];
    if (recipe.image && Buffer.isBuffer(recipe.image)) {
      recipe.image = `data:image/jpeg;base64,${recipe.image.toString('base64')}`;
    }

    const [ingredients] = await db.query(
      'SELECT i.name, ri.amount FROM recipe_ingredients ri JOIN ingredients i ON ri.ingredient_id = i.id WHERE ri.recipe_id = ?',
      [recipeId]
    );

    const [steps] = await db.query(
      'SELECT instruction FROM recipe_steps WHERE recipe_id = ? ORDER BY step_number ASC',
      [recipeId]
    );

    recipe.ingredients = ingredients;
    recipe.steps = steps.map((s) => s.instruction);

    res.json(recipe);
  } catch (err) {
    console.error('Fetch Recipe Detail Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ดึงหมวดหมู่ทั้งหมด
app.get('/api/categories', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM categories');
    res.json(rows);
  } catch (err) {
    console.error('Fetch Categories Error:', err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงหมวดหมู่' });
  }
});

// ==========================================
// 3. BOOKMARKS API
// ==========================================

// ดึงสูตรโปรดของผู้ใช้
app.get('/api/bookmarks', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT recipe_id FROM bookmarks WHERE user_id = ?', [req.user.id]);
    res.json(rows.map((r) => r.recipe_id));
  } catch (err) {
    console.error('Fetch Bookmarks Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// สลับเปิด/ปิด สูตรโปรด
app.post('/api/bookmarks/toggle', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { recipe_id } = req.body;

    const [existing] = await db.query(
      'SELECT * FROM bookmarks WHERE user_id = ? AND recipe_id = ?',
      [userId, recipe_id]
    );

    if (existing.length > 0) {
      await db.query('DELETE FROM bookmarks WHERE user_id = ? AND recipe_id = ?', [userId, recipe_id]);
      res.json({ bookmarked: false, message: 'ลบออกจากสูตรโปรดเรียบร้อย' });
    } else {
      await db.query('INSERT INTO bookmarks (user_id, recipe_id) VALUES (?, ?)', [userId, recipe_id]);
      res.json({ bookmarked: true, message: 'บันทึกเป็นสูตรโปรดเรียบร้อย' });
    }
  } catch (err) {
    console.error('Toggle Bookmark Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ==========================================
// 4. CREATE & DELETE RECIPES
// ==========================================

// เพิ่มสูตรอาหาร
app.post('/api/recipes', authenticateToken, async (req, res) => {
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const userId = req.user.id;
    const { title, description, category_id, image, ingredients, steps } = req.body;

    let imageBuffer = null;
    if (image && image.includes('base64,')) {
      const base64Data = image.split('base64,')[1];
      imageBuffer = Buffer.from(base64Data, 'base64');
    }

    const [recipeResult] = await connection.query(
      'INSERT INTO recipes (title, description, category_id, image, user_id) VALUES (?, ?, ?, ?, ?)',
      [title, description, category_id, imageBuffer, userId]
    );
    const recipeId = recipeResult.insertId;

    if (ingredients && ingredients.length > 0) {
      for (const ing of ingredients) {
        if (!ing.name || !ing.name.trim()) continue;

        let [ingRows] = await connection.query('SELECT id FROM ingredients WHERE name = ?', [ing.name.trim()]);
        let ingredientId;

        if (ingRows.length > 0) {
          ingredientId = ingRows[0].id;
        } else {
          const [newIng] = await connection.query('INSERT INTO ingredients (name) VALUES (?)', [ing.name.trim()]);
          ingredientId = newIng.insertId;
        }

        await connection.query(
          'INSERT INTO recipe_ingredients (recipe_id, ingredient_id, amount) VALUES (?, ?, ?)',
          [recipeId, ingredientId, ing.amount || '']
        );
      }
    }

    if (steps && steps.length > 0) {
      for (let i = 0; i < steps.length; i++) {
        if (steps[i] && steps[i].trim() !== '') {
          await connection.query(
            'INSERT INTO recipe_steps (recipe_id, step_number, instruction) VALUES (?, ?, ?)',
            [recipeId, i + 1, steps[i].trim()]
          );
        }
      }
    }

    await connection.commit();
    res.status(201).json({ message: 'เพิ่มสูตรอาหารเรียบร้อยแล้ว!', recipeId });
  } catch (err) {
    await connection.rollback();
    console.error('Create Recipe Error:', err);
    res.status(500).json({ message: err.message });
  } finally {
    connection.release();
  }
});

// ลบสูตรอาหาร
app.delete('/api/recipes/:id', authenticateToken, async (req, res) => {
  try {
    const recipeId = req.params.id;
    const currentUserId = req.user.id;
    const currentUserRole = req.user.role;

    const [recipes] = await db.query('SELECT user_id FROM recipes WHERE id = ?', [recipeId]);
    if (recipes.length === 0) {
      return res.status(404).json({ message: 'ไม่พบสูตรอาหารที่ต้องการลบ' });
    }

    const recipe = recipes[0];
    const isAdmin = currentUserRole === 'admin';
    const isOwner = recipe.user_id === currentUserId;

    if (!isAdmin && !isOwner) {
      return res.status(403).json({ message: 'คุณสามารถลบได้เฉพาะสูตรอาหารที่ตัวเองสร้างเท่านั้น' });
    }

    await db.query('DELETE FROM recipes WHERE id = ?', [recipeId]);
    res.json({ message: 'ลบสูตรอาหารเรียบร้อยแล้ว' });
  } catch (err) {
    console.error('Delete Recipe Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ------------------------------------------
// Start Server
// ------------------------------------------
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running with Cookie Auth on port ${PORT}`);
});