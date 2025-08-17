const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'super-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000*60*60*8 }
}));
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 100, standardHeaders: true });
app.use(['/login','/register','/contact','/lead'], authLimiter);
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const leadsFile = path.join(dataDir, 'leads.json');
const messagesFile = path.join(dataDir, 'messages.json');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
for (const f of [usersFile, leadsFile, messagesFile]) {
  if (!fs.existsSync(f)) fs.writeFileSync(f, '[]', 'utf-8');
}
const load = (file)=> JSON.parse(fs.readFileSync(file,'utf-8') || '[]');
const save = (file, data)=> fs.writeFileSync(file, JSON.stringify(data, null, 2));
function requireAuth(req, res, next){ if (req.session.user) return next(); return res.redirect('/login.html'); }

app.get('/', (req,res)=> res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/register', async (req,res)=>{
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing fields');
  const users = load(usersFile);
  if (users.find(u=>u.username.toLowerCase()===username.toLowerCase())) return res.status(409).send('Username already exists');
  const hash = await bcrypt.hash(password, 10);
  users.push({ id: uuidv4(), username, passwordHash: hash, createdAt: new Date().toISOString() });
  save(usersFile, users);
  req.session.user = { username };
  res.redirect('/dashboard');
});
app.post('/login', async (req,res)=>{
  const { username, password } = req.body;
  const users = load(usersFile);
  const u = users.find(x=>x.username === username);
  if (!u) return res.status(401).send('Invalid credentials');
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(401).send('Invalid credentials');
  req.session.user = { id: u.id, username: u.username };
  res.redirect('/dashboard');
});
app.post('/logout', (req,res)=>{ req.session.destroy(()=> res.redirect('/')); });
app.post('/lead', (req,res)=>{
  const { name, email, phone } = req.body;
  if (!name || !email) return res.status(400).json({ ok:false, msg:'Name & email required' });
  const leads = load(leadsFile);
  leads.push({ id: uuidv4(), name, email, phone: phone || '', createdAt: new Date().toISOString() });
  save(leadsFile, leads);
  res.json({ ok:true });
});
app.post('/contact', (req,res)=>{
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).send('All fields required');
  const messages = load(messagesFile);
  messages.push({ id: uuidv4(), name, email, message, createdAt: new Date().toISOString() });
  save(messagesFile, messages);
  res.redirect('/thanks.html');
});
app.get('/dashboard', requireAuth, (req,res)=>{
  const users = load(usersFile).map(u=>({ username: u.username, createdAt: u.createdAt }));
  const leads = load(leadsFile);
  const messages = load(messagesFile);
  res.render('dashboard', { user: req.session.user, users, leads, messages });
});
app.get('/health', (_,res)=> res.json({ ok:true }));

// ✅ IP set yahan
const MY_IP = '192.168.1.11';
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running locally → http://localhost:${PORT}`);
  console.log(`Access from Mobile   → http://${MY_IP}:${PORT}`);
});
