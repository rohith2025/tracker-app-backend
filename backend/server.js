// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();
app.use(cors({ origin: "mongodb+srv://tracker:tracker123@cluster0.fwhcsvm.mongodb.net/" }));
app.use(express.json());

const SECRET = "supersecretkey"; // JWT secret
const PORT = 5000;

// ------------------- Mongoose Models -------------------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "user"], default: "user" },
});

const questionSchema = new mongoose.Schema({
  name: { type: String, required: true },
  completedQuestions: [mongoose.Schema.Types.ObjectId], // user IDs
  completedRevision: [mongoose.Schema.Types.ObjectId],  // user IDs
});

const levelSchema = new mongoose.Schema({
  name: { type: String, required: true },
  questions: [questionSchema],
});

const topicSchema = new mongoose.Schema({
  name: { type: String, required: true },
  levels: [levelSchema],
  assignments: [{name: String }],
});

const User = mongoose.model("User", userSchema);
const Topic = mongoose.model("Topic", topicSchema);

// ------------------- Connect to MongoDB -------------------
mongoose.connect("mongodb+srv://tracker:tracker123@cluster0.fwhcsvm.mongodb.net/", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("MongoDB connected");
  seedAdminUser();
  seedTestUser();
});

// ------------------- Middleware -------------------
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ msg: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ msg: "User not found" });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ msg: "Invalid token" });
  }
};

// ------------------- Seed Admin -------------------
async function seedAdminUser() {
  const admin = await User.findOne({ email: "admin@dsa.com" });
  if (!admin) {
    const hashed = await bcrypt.hash("admin_123_09", 10);
    await User.create({
      username: "admin",
      email: "admin@dsa.com",
      password: hashed,
      role: "admin",
    });
    console.log("Admin user seeded");
  }
}

// ------------------- Seed Test User -------------------
async function seedTestUser() {
  const user = await User.findOne({ email: "user@dsa.com" });
  if (!user) {
    const hashed = await bcrypt.hash("user_123_09", 10);
    await User.create({
      username: "testuser",
      email: "user@dsa.com",
      password: hashed,
      role: "user",
    });
    console.log("Test user seeded");
  }
}

// ------------------- Auth Routes -------------------
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ msg: "Invalid credentials" });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ msg: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, role: user.role }, SECRET, { expiresIn: "7d" });
  res.json({ token, email: user.email, role: user.role, username: user.username});
});

// ------------------- Admin Routes (CRUD) -------------------
// Get all topics
app.get("/api/topics", authMiddleware, async (req, res) => {
  const topics = await Topic.find();
  res.json(topics);
});

// Create topic
app.post("/api/topics", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  const { name } = req.body;
  const topic = await Topic.create({ name, levels: [], assignments: [] });
  res.json(topic);
});

// Update topic
app.put("/api/topics/:topicId", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  const topic = await Topic.findById(req.params.topicId);
  if (!topic) return res.status(404).json({ msg: "Topic not found" });
  topic.name = req.body.name || topic.name;
  await topic.save();
  res.json(topic);
});

// Delete topic
app.delete("/api/topics/:topicId", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  await Topic.findByIdAndDelete(req.params.topicId);
  res.json({ msg: "Topic deleted" });
});

// -------- Levels CRUD --------
app.post("/api/topics/:topicId/levels", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  const topic = await Topic.findById(req.params.topicId);
  topic.levels.push({ name: req.body.name, questions: [] });
  await topic.save();
  res.json(topic);
});

app.put("/api/topics/:topicId/levels/:levelId", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  const topic = await Topic.findById(req.params.topicId);
  const level = topic.levels.id(req.params.levelId);
  if (!level) return res.status(404).json({ msg: "Level not found" });
  level.name = req.body.name || level.name;
  await topic.save();
  res.json(topic);
});

app.delete("/api/topics/:topicId/levels/:levelId", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  try {
    const topic = await Topic.findById(req.params.topicId);
    if (!topic) return res.status(404).json({ msg: "Topic not found" });

    topic.levels = topic.levels.filter(l => l._id.toString() !== req.params.levelId);
    await topic.save();

    res.json(topic);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// -------- Questions CRUD --------
app.post("/api/topics/:topicId/levels/:levelId/questions", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  const topic = await Topic.findById(req.params.topicId);
  const level = topic.levels.id(req.params.levelId);
  level.questions.push({ name: req.body.name });
  await topic.save();
  res.json(level);
});

app.put("/api/topics/:topicId/levels/:levelId/questions/:questionId", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  const topic = await Topic.findById(req.params.topicId);
  const level = topic.levels.id(req.params.levelId);
  const question = level.questions.id(req.params.questionId);
  question.name = req.body.name || question.name;
  await topic.save();
  res.json(level);
});

app.delete("/api/topics/:topicId/levels/:levelId/questions/:questionId", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
  try {
    const topic = await Topic.findById(req.params.topicId);
    if (!topic) return res.status(404).json({ msg: "Topic not found" });

    const level = topic.levels.id(req.params.levelId);
    if (!level) return res.status(404).json({ msg: "Level not found" });

    level.questions = level.questions.filter(q => q._id.toString() !== req.params.questionId);
    await topic.save();

    res.json(level);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// // -------- Assignments CRUD --------
// import { Types } from "mongoose";

// // Add assignment
// app.post("/api/topics/:topicId/assignments", authMiddleware, async (req, res) => {
//   if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
//   const topic = await Topic.findById(req.params.topicId);
//   const newAssignment = { _id: new Types.ObjectId(), name: req.body.name };
//   topic.assignments.push(newAssignment);
//   await topic.save();
//   res.json(topic);
// });

// // Update assignment
// app.put("/api/topics/:topicId/assignments/:assignmentId", authMiddleware, async (req, res) => {
//   if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
//   const topic = await Topic.findById(req.params.topicId);
//   const assignment = topic.assignments.id(req.params.assignmentId);
//   if (!assignment) return res.status(404).json({ msg: "Assignment not found" });
//   assignment.name = req.body.name || assignment.name;
//   await topic.save();
//   res.json(topic);
// });

// // Delete assignment
// app.delete("/api/topics/:topicId/assignments/:assignmentId", authMiddleware, async (req, res) => {
//   if (req.user.role !== "admin") return res.status(403).json({ msg: "Forbidden" });
//   try {
//     const topic = await Topic.findById(req.params.topicId);
//     if (!topic) return res.status(404).json({ msg: "Topic not found" });

//     topic.assignments = topic.assignments.filter(a => a._id.toString() === req.params.assignmentId ? false : true);
//     await topic.save();

//     res.json(topic);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ msg: "Server error" });
//   }
// });

// -------- User Progress --------
app.get("/api/progress", authMiddleware, async (req, res) => {
  const userId = req.user._id;
  const topics = await Topic.find();
  const progressData = topics.map(t => ({
    _id: t._id,
    name: t.name,
    levels: t.levels.map(l => ({
      _id: l._id,
      name: l.name,
      questions: l.questions.map(q => ({
        _id: q._id,
        name: q.name,
        completedQuestions: q.completedQuestions.includes(userId),
        completedRevision: q.completedRevision.includes(userId),
      })),
    })),
  }));
  res.json(progressData);
});

app.post("/api/progress", authMiddleware, async (req, res) => {
  const { topicId, levelId, questionId, tab, completed } = req.body;
  const userId = req.user._id;

  const topic = await Topic.findById(topicId);
  if (!topic) return res.status(404).json({ msg: "Topic not found" });
  
  const level = topic.levels.id(levelId);
  if (!level) return res.status(404).json({ msg: "Level not found" });

  const question = level.questions.id(questionId);
  if (!question) return res.status(404).json({ msg: "Question not found" });

  const arr = tab === "questions" ? question.completedQuestions : question.completedRevision;

  if (completed) {
    if (!arr.includes(userId)) arr.push(userId);
  } else {
    if (tab === "questions") {
      question.completedQuestions = question.completedQuestions.filter(u => !u.equals(userId));
    } else {
      question.completedRevision = question.completedRevision.filter(u => !u.equals(userId));
    }
  }

  await topic.save();
  res.json({ msg: "Progress updated" });
});


app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const user = req.user; // from authMiddleware
  res.json({ username: user.username, email: user.email, role: user.role });
});



// ------------------- Start Server -------------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
