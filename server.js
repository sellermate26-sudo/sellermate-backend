// SellerMate Backend Server
// Run: npm install   then   node server.js
// Also run: npm install @supabase/supabase-js
// Then uncomment the supabase line below

var express = require("express");
var cors = require("cors");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
// UNCOMMENT after npm install:
// var supabaseJs = require("@supabase/supabase-js");
// var supabase = supabaseJs.createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

var app = express();
app.use(cors());
app.use(express.json());

var JWT_SECRET = process.env.JWT_SECRET || "sellermate_secret_2025";
var ADMIN_KEY  = process.env.ADMIN_KEY  || "SMKEY-2025-SELLRM8";

function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  var header = req.headers.authorization || "";
  var token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.json({ success: false, message: "Invalid token" });
  }
}

app.post("/api/auth/signup", async function(req, res) {
  var email = req.body.email;
  var password = req.body.password;
  var name = req.body.name;
  if (!email || !password) return res.json({ success: false, message: "Email and password required" });
  var hash = await bcrypt.hash(password, 10);
  var result = await supabase.from("users").insert([{ email: email, password_hash: hash, name: name }]).select().single();
  if (result.error) return res.json({ success: false, message: "Email already registered" });
  var data = result.data;
  res.json({ success: true, token: makeToken(data), user: { id: data.id, email: data.email, name: data.name, plan: data.plan, expiresAt: data.expires_at } });
});

app.post("/api/auth/login", async function(req, res) {
  var email = req.body.email;
  var password = req.body.password;
  var result = await supabase.from("users").select("*").eq("email", email).single();
  if (result.error || !result.data) return res.json({ success: false, message: "Email not found" });
  var data = result.data;
  var match = await bcrypt.compare(password, data.password_hash);
  if (!match) return res.json({ success: false, message: "Wrong password" });
  res.json({ success: true, token: makeToken(data), user: { id: data.id, email: data.email, name: data.name, plan: data.plan, expiresAt: data.expires_at } });
});

app.get("/api/auth/verify", authMiddleware, async function(req, res) {
  var result = await supabase.from("users").select("*").eq("id", req.user.id).single();
  if (!result.data) return res.json({ success: false });
  var data = result.data;
  res.json({ success: true, user: { id: data.id, email: data.email, name: data.name, plan: data.plan, expiresAt: data.expires_at } });
});

app.post("/api/admin/activate", async function(req, res) {
  if (req.body.adminKey !== ADMIN_KEY) return res.json({ success: false, message: "Invalid admin key" });
  var email = req.body.email;
  var days = req.body.days || 30;
  var expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  await supabase.from("users").update({ plan: "pro", expires_at: expiresAt }).eq("email", email);
  res.json({ success: true, message: email + " activated for " + days + " days" });
});

app.post("/api/admin/users", async function(req, res) {
  if (req.body.adminKey !== ADMIN_KEY) return res.json({ success: false });
  var result = await supabase.from("users").select("email,name,plan,expires_at,created_at").order("created_at", { ascending: false });
  res.json({ success: true, users: result.data });
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log("SellerMate API running on port " + PORT);
});