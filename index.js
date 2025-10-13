import express from "express";
import session from "express-session";
import passport from "passport";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import pg from "pg";
import multer from "multer";
import path from "path";
import env from "dotenv";

env.config();

const app = express();
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

db.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Connection error", err.stack));

app.use(bodyParser.urlencoded({ extended: true }));

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use("/uploads", express.static("uploads")); // for images

// Middleware for protected routes
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// ================= ROUTES =================

// 🏠 HOME PAGE (includes featured post)
app.get("/", async (req, res) => {
  try {
    // Random featured post
    const featuredResult = await db.query(`
      SELECT posts.id, posts.title, posts.content, posts.image, users.username AS author
      FROM posts
      JOIN users ON posts.user_id = users.id
      ORDER BY RANDOM()
      LIMIT 1
    `);
    const featuredPost = featuredResult.rows[0] || null;

    // All posts for the blog section
    const postsResult = await db.query(`
      SELECT posts.id, posts.title, posts.content, posts.image, users.username AS author
      FROM posts
      JOIN users ON posts.user_id = users.id
      ORDER BY posts.id DESC
    `);

    res.render("home", {
      user: req.user,
      featuredPost,
      posts: postsResult.rows,
    });
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.render("home", { user: req.user, featuredPost: null, posts: [] });
  }
});

// ================= AUTH =================
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password, confirmP } = req.body;
  if (password !== confirmP) return res.status(400).send("Passwords do not match!");

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
      [name, email, hashedPassword]
    );
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error registering user");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(401).send("Invalid email or password");

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).send("Invalid email or password");

    req.login(user, (err) => {
      if (err) return next(err);
      res.redirect("/");
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).send("Server error");
  }
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// ================= POSTS =================

// File upload setup (multer)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Create new post
app.get("/post", ensureAuth, (req, res) => {
  res.render("post", { user: req.user });
});

app.post("/post", ensureAuth, upload.single("image"), async (req, res) => {
  const { title, content } = req.body;
  const imagePath = req.file ? "/uploads/" + req.file.filename : null;

  try {
    await db.query(
      "INSERT INTO posts (title, content, user_id, image) VALUES ($1, $2, $3, $4)",
      [title, content, req.user.id, imagePath]
    );
    res.redirect("/");
  } catch (error) {
    console.error("Post creation failed:", error);
    res.status(500).send("Failed to create post.");
  }
});

// My posts page
app.get("/myposts", ensureAuth, async (req, res) => {
  try {
    const result = await db.query(
      `
      SELECT posts.id, posts.title, posts.content, posts.image, users.username AS author
      FROM posts
      JOIN users ON posts.user_id = users.id
      WHERE users.id = $1
      ORDER BY posts.id DESC
      `,
      [req.user.id]
    );
    res.render("myposts", { user: req.user, posts: result.rows });
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.render("myposts", { user: req.user, posts: [] });
  }
});

// Edit post
app.get("/post/edit/:id", ensureAuth, async (req, res) => {
  const postId = req.params.id;
  try {
    const result = await db.query("SELECT * FROM posts WHERE id = $1 AND user_id = $2", [
      postId,
      req.user.id,
    ]);
    if (result.rows.length === 0) return res.status(404).send("Post not found or unauthorized.");

    res.render("editPost", { user: req.user, post: result.rows[0] });
  } catch (error) {
    console.error("Error loading post for edit:", error);
    res.status(500).send("Error loading post for edit.");
  }
});

app.post("/post/edit/:id", ensureAuth, upload.single("image"), async (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;
  const newImagePath = req.file ? "/uploads/" + req.file.filename : null;

  try {
    if (newImagePath) {
      await db.query(
        "UPDATE posts SET title = $1, content = $2, image = $3 WHERE id = $4 AND user_id = $5",
        [title, content, newImagePath, postId, req.user.id]
      );
    } else {
      await db.query(
        "UPDATE posts SET title = $1, content = $2 WHERE id = $3 AND user_id = $4",
        [title, content, postId, req.user.id]
      );
    }
    res.redirect("/myposts");
  } catch (error) {
    console.error("Error updating post:", error);
    res.status(500).send("Error updating post.");
  }
});

// Delete post
app.post("/post/delete/:id", ensureAuth, async (req, res) => {
  const postId = req.params.id;
  try {
    await db.query("DELETE FROM posts WHERE id = $1 AND user_id = $2", [postId, req.user.id]);
    res.redirect("/myposts");
  } catch (error) {
    console.error("Error deleting post:", error);
    res.status(500).send("Error deleting post.");
  }
});

// Show single post page
app.get("/posts/:id", async (req, res) => {
  const postId = req.params.id;

  try {
    const result = await db.query(
      `SELECT posts.id, posts.title, posts.content, posts.image, users.username AS author
       FROM posts
       JOIN users ON posts.user_id = users.id
       WHERE posts.id = $1`,
      [postId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Post not found");
    }

    const post = result.rows[0];
    res.render("postDetail", { user: req.user, post });
  } catch (error) {
    console.error("Error fetching post:", error);
    res.status(500).send("Server error");
  }
});


// ================= PASSPORT =================
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// ================= SERVER =================
app.listen(3000, () => {
  console.log("🚀 Server running on http://localhost:3000");
});
