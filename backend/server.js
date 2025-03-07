const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const app = express();

// Configure CORS to allow requests from frontend
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type']
}));

// Increase payload size limit for image uploads
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Kết nối SQLite
const db = new sqlite3.Database("./mente.db", (err) => {
  if (err) console.error(err.message);
  else console.log("✅ Connected to SQLite database");
});

// Tạo bảng users nếu chưa có
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  first_name TEXT,
  last_name TEXT,
  phone TEXT,
  birth TEXT,
  gender TEXT,
  profile_picture TEXT
)`);

// Add profile_picture column if it doesn't exist
db.run(`ALTER TABLE users ADD COLUMN profile_picture TEXT`, (err) => {
  if (err && !err.message.includes('duplicate column')) {
    console.error('Error adding profile_picture column:', err);
  }
});

// Tạo bảng mood_tracking với foreign key
db.run(`CREATE TABLE IF NOT EXISTS mood_tracking (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  date TEXT,
  mood TEXT,
  FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
)`);

// Tạo bảng journals với foreign key
db.run(`CREATE TABLE IF NOT EXISTS journals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  title TEXT,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
)`);

// Tạo bảng goals với foreign key
db.run(`CREATE TABLE IF NOT EXISTS goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  name TEXT,
  progress INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
)`);

// 📌 API ĐĂNG KÝ
app.post("/register", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (user) {
      return res.status(400).json({ error: "Email already exists" });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.status(500).json({ error: "Internal server error" });
      }

      db.run(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        [email, hashedPassword],
        (err) => {
          if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Database error" });
          }
          res.json({ message: "User registered successfully" });
        }
      );
    });
  });
});

// 📌 API ĐĂNG NHẬP
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    bcrypt.compare(password, user.password, (err, match) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).json({ error: "Internal server error" });
      }
      if (!match) {
        return res.status(400).json({ error: "Invalid email or password" });
      }

      res.json({ message: "Login successful", username: email.split("@")[0] });
    });
  });
});


// 📌 Cập nhật bảng users để lưu thông tin cá nhân
db.run(`ALTER TABLE users ADD COLUMN first_name TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN last_name TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN birth TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN gender TEXT`, () => {});

// 📌 API Cập nhật thông tin cá nhân
app.put("/update-profile", (req, res) => {
  const { email, first_name, last_name, phone, birth, gender } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const sql = `
    UPDATE users 
    SET first_name = ?, last_name = ?, phone = ?, birth = ?, gender = ?
    WHERE email = ?
  `;

  db.run(sql, [first_name, last_name, phone, birth, gender, email], function (err) {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (this.changes === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    // Return updated user data
    db.get(
      "SELECT first_name, last_name, email, phone, birth, gender, profile_picture FROM users WHERE email = ?",
      [email],
      (err, user) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ error: "Database error" });
        }
        res.json({ message: "Profile updated successfully", user });
      }
    );
  });
});

// 📌 API Đổi mật khẩu
app.put("/change-password", (req, res) => {
  const { email, old_password, new_password } = req.body;

  if (!email || !old_password || !new_password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Kiểm tra xem email có tồn tại không
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    // Kiểm tra mật khẩu cũ
    bcrypt.compare(old_password, user.password, (err, match) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).json({ error: "Internal server error" });
      }
      if (!match) {
        return res.status(400).json({ error: "Old password is incorrect" });
      }

      // Mã hóa mật khẩu mới
      bcrypt.hash(new_password, 10, (err, hashedPassword) => {
        if (err) {
          console.error("Error hashing password:", err);
          return res.status(500).json({ error: "Internal server error" });
        }

        // Cập nhật mật khẩu
        db.run(
          "UPDATE users SET password = ? WHERE email = ?",
          [hashedPassword, email],
          function (err) {
            if (err) {
              console.error("Database error:", err);
              return res.status(500).json({ error: "Database error" });
            }
            res.json({ message: "Password changed successfully" });
          }
        );
      });
    });
  });
});

  
  // 📌 API Lấy thông tin cá nhân
app.get("/profile", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  console.log("Fetching profile for email:", email); // Add logging

  db.get(
    "SELECT first_name, last_name, email, phone, birth, gender, profile_picture FROM users WHERE email = ?",
    [email],
    (err, user) => {
      if (err) {
        console.error("Database error when fetching profile:", err);
        return res.status(500).json({ error: "Database error", details: err.message });
      }

      console.log("Found user:", user ? "yes" : "no"); // Add logging

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Ensure all fields exist even if null
      const safeUser = {
        first_name: user.first_name || null,
        last_name: user.last_name || null,
        email: user.email,
        phone: user.phone || null,
        birth: user.birth || null,
        gender: user.gender || null,
        profile_picture: user.profile_picture || null
      };

      res.json(safeUser);
    }
  );
});
  


  // 📌 API Ghi lại mood (cho phép nhiều mood trong cùng 1 ngày)
app.post("/log-mood", (req, res) => {
  const { email, date, mood } = req.body;

  if (!email || !date || !mood) {
    return res.status(400).json({ error: "Email, date, and mood are required" });
  }

  db.run(
    "INSERT INTO mood_tracking (email, date, mood) VALUES (?, ?, ?)",
    [email, date, mood],
    (err) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json({ message: "Mood logged successfully" });
    }
  );
});

// 📌 API Lấy toàn bộ lịch sử mood của người dùng
app.get("/mood-history", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  db.all(
    `SELECT date, mood FROM mood_tracking 
     WHERE email = ?
     ORDER BY date ASC`, // Lấy toàn bộ mood theo thứ tự ngày
    [email],
    (err, rows) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      // Chỉ giữ lại mood mới nhất của mỗi ngày
      const latestMoods = {};
      rows.forEach((entry) => {
        latestMoods[entry.date] = entry.mood;
      });

      res.json(Object.keys(latestMoods).map((date) => ({
        date,
        mood: latestMoods[date],
      })));
    }
  );
});



// 📌 Tạo bảng folders nếu chưa có
db.run(`DROP TABLE IF EXISTS journal_entries`);
db.run(`DROP TABLE IF EXISTS folders`);

db.run(`CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  title TEXT NOT NULL,
  color TEXT DEFAULT '#d4a76a',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
)`);

// 📌 API LẤY DANH SÁCH FOLDER
app.get("/folders", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  db.all("SELECT * FROM folders WHERE email = ? ORDER BY created_at DESC", [email], (err, rows) => {
    if (err) {
      console.error("Error fetching folders:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows);
  });
});

// 📌 API THÊM FOLDER MỚI
app.post("/folders", (req, res) => {
  const { email, title } = req.body;

  if (!email || !title) {
    return res.status(400).json({ error: "Email and title are required" });
  }

  db.run(
    "INSERT INTO folders (email, title) VALUES (?, ?)",
    [email, title],
    function(err) {
      if (err) {
        console.error("Error creating folder:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json({
        id: this.lastID,
        email,
        title,
        color: '#d4a76a',
        created_at: new Date().toISOString()
      });
    }
  );
});

// 📌 API XÓA FOLDER
app.delete("/folders", (req, res) => {
  const { folderIds } = req.body;
  if (!folderIds || !folderIds.length) {
    return res.status(400).json({ error: "Folder IDs are required" });
  }

  db.run(`DELETE FROM folders WHERE id IN (${folderIds.map(() => "?").join(",")})`, folderIds, function (err) {
    if (err) {
      console.error("Error deleting folders:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ message: "Folders deleted successfully" });
  });
});


// 📌 Tạo bảng journal_entries nếu chưa có
db.run(`CREATE TABLE IF NOT EXISTS journal_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folder_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT,
  color TEXT DEFAULT '#d4a76a',
  date DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
)`);

// 📌 API LẤY DANH SÁCH ENTRIES TRONG FOLDER
app.get("/folders/:folderId/entries", (req, res) => {
  const { folderId } = req.params;

  db.all(
    "SELECT e.*, f.title as folder_title, f.color as folder_color FROM journal_entries e LEFT JOIN folders f ON e.folder_id = f.id WHERE e.folder_id = ? ORDER BY e.date DESC",
    [folderId],
    (err, rows) => {
      if (err) {
        console.error("Error fetching entries:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json(rows);
    }
  );
});

// 📌 API THÊM JOURNAL ENTRY MỚI
app.post("/folders/:folderId/entries", (req, res) => {
  const { folderId } = req.params;
  const { title, content, color, date } = req.body;

  if (!title) {
    return res.status(400).json({ error: "Title is required" });
  }

  db.run(
    "INSERT INTO journal_entries (folder_id, title, content, color, date) VALUES (?, ?, ?, ?, ?)",
    [folderId, title, content || '', color || '#d4a76a', date || new Date().toISOString()],
    function(err) {
      if (err) {
        console.error("Error creating entry:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json({
        id: this.lastID,
        folder_id: folderId,
        title,
        content: content || '',
        color: color || '#d4a76a',
        date: date || new Date().toISOString()
      });
    }
  );
});

// 📌 API XÓA JOURNAL ENTRY
// 📌 API XÓA NHIỀU ENTRIES CÙNG LÚC
app.delete("/folders/:folderId/entries", (req, res) => {
  const { entryIds } = req.body;

  if (!entryIds || !entryIds.length) {
    return res.status(400).json({ error: "Entry IDs are required" });
  }

  db.run(
    `DELETE FROM journal_entries WHERE id IN (${entryIds.map(() => "?").join(",")})`,
    entryIds,
    function (err) {
      if (err) {
        console.error("Error deleting journal entries:", err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json({ message: "Entries deleted successfully" });
    }
  );
});




// 📌 API lấy chi tiết Entry theo ID
app.get("/entries/:entryId", (req, res) => {
  const { entryId } = req.params;

  db.get(
    "SELECT e.*, f.title as folder_title, f.color as folder_color FROM journal_entries e LEFT JOIN folders f ON e.folder_id = f.id WHERE e.id = ?",
    [entryId],
    (err, row) => {
      if (err) {
        console.error("Error fetching entry:", err);
        return res.status(500).json({ error: "Database error" });
      }
      if (!row) {
        return res.status(404).json({ error: "Entry not found" });
      }
      res.json(row);
    }
  );
});





// 📌 Tạo bảng goals nếu chưa có
db.run(`CREATE TABLE IF NOT EXISTS goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  progress INTEGER NOT NULL
)`);

// 📌 API Lấy danh sách Goals
app.get("/goals", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  db.all("SELECT * FROM goals WHERE email = ?", [email], (err, rows) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows);
  });
});

// 📌 API Thêm Goal mới
app.post("/goals", (req, res) => {
  const { email, name, progress } = req.body;

  if (!email || !name || progress === undefined) {
    return res.status(400).json({ error: "Email, name, and progress are required" });
  }

  db.run("INSERT INTO goals (email, name, progress) VALUES (?, ?, ?)", [email, name, progress], function (err) {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ id: this.lastID, name, progress });
  });
});

// 📌 API Cập nhật Progress của Goal
app.put("/goals/:goalId", (req, res) => {
  const { goalId } = req.params;
  const { progress } = req.body;

  if (progress === undefined) {
    return res.status(400).json({ error: "Progress is required" });
  }

  db.run("UPDATE goals SET progress = ? WHERE id = ?", [progress, goalId], function (err) {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ message: "Goal updated successfully" });
  });
});

// 📌 API Xóa Goal
app.delete("/goals/:goalId", (req, res) => {
  const { goalId } = req.params;

  db.run("DELETE FROM goals WHERE id = ?", [goalId], function (err) {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ message: "Goal deleted successfully" });
  });
});




// 🚀 Tạo bảng nếu chưa có
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS quiz_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS quiz_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    question_id INTEGER NOT NULL,
    answer TEXT NOT NULL,
    FOREIGN KEY (question_id) REFERENCES quiz_questions(id)
  )`);

  // 📌 Danh sách câu hỏi quiz
  const quizQuestions = [
    "I often feel anxious, stressed, or worried, even when there's no clear reason.",
    "I struggle with feelings of sadness or emptiness that last for days or weeks.",
    "I find it hard to concentrate or stay motivated, even on tasks I usually enjoy.",
    "I feel emotionally supported by the people in my life (friends, family, or a community).",
    "I have healthy ways to cope with stress and difficult emotions.",
    "I experience sudden mood swings or emotions that feel overwhelming.",
    "I feel confident in myself and my ability to handle challenges.",
    "I have trouble sleeping (falling asleep, staying asleep, or sleeping too much).",
    "I feel hopeful about my future and excited about things to come.",
    "I sometimes have thoughts of hurting myself or feeling like I don't want to be here."
  ];

  // Thêm câu hỏi vào database nếu chưa tồn tại
  quizQuestions.forEach((question) => {
    db.run(
      "INSERT INTO quiz_questions (question) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM quiz_questions WHERE question = ?)",
      [question, question]
    );
  });

  console.log("✅ Quiz questions initialized.");
});

// 📌 API lấy danh sách câu hỏi quiz
app.get("/quiz-questions", (req, res) => {
  db.all("SELECT * FROM quiz_questions", [], (err, rows) => {
    if (err) {
      console.error("❌ Error fetching quiz questions:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows);
  });
});

// 📌 API lưu câu trả lời quiz
app.post("/quiz-submit", (req, res) => {
  const { email, answers } = req.body;

  if (!email || !answers || !Array.isArray(answers) || answers.length !== 10) {
    return res.status(400).json({ error: "Invalid input data" });
  }

  const insertPromises = answers.map(({ question_id, answer }) => {
    return new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO quiz_answers (email, question_id, answer) VALUES (?, ?, ?)",
        [email, question_id, answer],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  });

  Promise.all(insertPromises)
    .then(() => res.json({ message: "Quiz answers saved successfully" }))
    .catch((err) => {
      console.error("❌ Database error:", err);
      res.status(500).json({ error: "Database error" });
    });
});






// API lấy dữ liệu phân tích Mood cho tất cả các ngày
app.get("/mood-analytics", (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  db.all(
    `SELECT date, mood FROM mood_tracking WHERE email = ? ORDER BY date ASC`,
    [email],
    (err, rows) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (!rows.length) {
        return res.json({ hasData: false }); // Không có dữ liệu
      }

      // Chuyển đổi mood thành giá trị số
      const moodMapping = {
        "Overwhelmed": 1,
        "Sad": 2,
        "Neutral": 3,
        "Happy": 4,
        "Ecstatic": 5,
      };

      let weeklyData = {}; // Dữ liệu theo từng ngày trong tuần (0 - 6)
      let monthlyData = {}; // Dữ liệu theo từng tháng (0 - 11)
      let stressLevels = {}; // Stress level theo từng ngày trong tuần
      let moodScores = []; // Tổng hợp mood scores để tính tổng thể 
      let dailyData = {}; // Dữ liệu theo từng ngày

      rows.forEach(({ date, mood }) => {
        const score = moodMapping[mood] || 3; // Mặc định là Neutral (3) nếu không tìm thấy
        const stress = 100 - ((score / 5) * 100); // Stress level = 100 - (mood score * 20)
        const dayOfWeek = new Date(date).getDay(); // 0 (Chủ Nhật) - 6 (Thứ Bảy)
        const month = new Date(date).getMonth(); // 0 - 11

        // Dữ liệu theo tuần
        if (!weeklyData[dayOfWeek]) weeklyData[dayOfWeek] = []; // Khởi tạo mảng nếu chưa có dữ liệu cho ngày đó
        weeklyData[dayOfWeek].push(score); // Thêm mood score vào mảng array

        // Dữ liệu theo tháng
        if (!monthlyData[month]) monthlyData[month] = [];
        monthlyData[month].push(score);

        // Stress level theo thứ trong tuần
        if (!stressLevels[dayOfWeek]) stressLevels[dayOfWeek] = [];
        stressLevels[dayOfWeek].push(stress);

        // Lưu toàn bộ mood để tính average tổng thể
        moodScores.push(score); // Thêm mood score vào mảng

        // Dữ liệu theo ngày (sử dụng date string, giả sử định dạng ISO: "YYYY-MM-DD")
        if (!dailyData[date]) {
          dailyData[date] = { totalScore: score, totalStress: stress, count: 1 };
        } else {
          dailyData[date].totalScore += score; //total score: tổng điểm mood của ngày đó
          dailyData[date].totalStress += stress; //total stress: tổng stress của ngày đó
          dailyData[date].count += 1; //count: số lần mood được ghi lại trong ngày
        }
      });

      // Tính trung bình mood theo tuần (sắp xếp theo thứ tự 0 đến 6)
      const weeklyMoodTrend = Object.keys(weeklyData)     // Lấy danh sách các ngày trong tuần
        .sort((a, b) => a - b)                  // Sắp xếp theo thứ tự tăng dần (0 - 6)
        .map(day => {                          // Duyệt qua từng ngày
          const arr = weeklyData[day];        // Lấy mảng mood score của ngày đó
          return arr.reduce((sum, val) => sum + val, 0) / arr.length; // Tính trung bình mood
        });

      // Tính trung bình mood theo tháng (sắp xếp theo thứ tự tháng)
      const monthlyMoodTrend = Object.keys(monthlyData)
        .sort((a, b) => a - b)
        .map(month => {
          const arr = monthlyData[month];
          return arr.reduce((sum, val) => sum + val, 0) / arr.length;
        });

      // Tính trung bình stress theo tuần
      const weeklyStressAvg = Object.keys(stressLevels)
        .sort((a, b) => a - b)
        .map(day => {
          const arr = stressLevels[day];
          return arr.reduce((sum, val) => sum + val, 0) / arr.length;
        });

      // Tạo mảng dailyAnalytics: mỗi mục gồm date, avgMood và stressLevel (đã làm tròn 1 số thập phân)
      const dailyAnalytics = Object.keys(dailyData)
        .sort() // Sắp xếp theo chuỗi ngày (định dạng ISO giúp sắp xếp đúng thứ tự)
        .map(date => {
          const { totalScore, totalStress, count } = dailyData[date];
          const avgMood = totalScore / count;
          const avgStress = totalStress / count;
          return { date, avgMood: +avgMood.toFixed(1), stressLevel: +avgStress.toFixed(1) };
        });

      // Tính toán insights tổng thể
      const avgMoodOverall = (moodScores.reduce((sum, val) => sum + val, 0) / moodScores.length).toFixed(1);
      // Tìm ngày có mức stress cao nhất từ dailyAnalytics
      const highestStressDayObj = dailyAnalytics.reduce((prev, current) =>
        prev.stressLevel > current.stressLevel ? prev : current
      );
      const highestStressDay = highestStressDayObj.date;

      res.json({
        hasData: true,
        dailyAnalytics,         // Dữ liệu từng ngày
        weeklyMoodTrend,        // Trung bình theo thứ trong tuần
        monthlyMoodTrend,       // Trung bình theo tháng
        weeklyStressLevels: weeklyStressAvg, // Stress theo thứ trong tuần
        insights: {
          avgMood: avgMoodOverall,
          highestStressDay,
        },
      });
    }
  );
});



// 📌 API Update profile picture
app.put("/update-profile-picture", (req, res) => {
  const { email, profile_picture } = req.body;

  if (!email || !profile_picture) {
    return res.status(400).json({ error: "Email and profile picture are required" });
  }

  console.log("Updating profile picture for email:", email); // Add logging
  console.log("Profile picture size:", profile_picture.length / 1024 / 1024, "MB"); // Log size

  // Check if base64 string is too large (max 5MB after base64 encoding)
  if (profile_picture.length > 7 * 1024 * 1024) { // ~5MB after base64 encoding
    return res.status(413).json({ error: "Profile picture is too large. Maximum size is 5MB" });
  }

  db.run(
    "UPDATE users SET profile_picture = ? WHERE email = ?",
    [profile_picture, email],
    function (err) {
      if (err) {
        console.error("Database error when updating profile picture:", err);
        return res.status(500).json({ error: "Database error", details: err.message });
      }

      console.log("Rows affected:", this.changes); // Add logging

      if (this.changes === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      res.json({ message: "Profile picture updated successfully" });
    }
  );
});

// 📌 API UPDATE JOURNAL ENTRY
app.put("/entries/:entryId", (req, res) => {
  const { entryId } = req.params;
  const { content, updated_at } = req.body;

  db.run(
    "UPDATE journal_entries SET content = ?, date = ? WHERE id = ?",
    [content, updated_at, entryId],
    function(err) {
      if (err) {
        console.error("Error updating entry:", err);
        return res.status(500).json({ error: "Database error" });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: "Entry not found" });
      }
      res.json({ message: "Entry updated successfully" });
    }
  );
});

// 📌 KHỞI CHẠY SERVER
const PORT = 5001;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
