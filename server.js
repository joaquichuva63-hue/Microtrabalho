// Simple Express server with SQLite for demo purposes
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.use('/css', express.static(path.join(__dirname, '..', 'css')));
app.use('/js', express.static(path.join(__dirname, '..', 'js')));

const DB_PATH = path.join(__dirname, 'microtasks.db');
const db = new sqlite3.Database(DB_PATH);

const JWT_SECRET = process.env.JWT_SECRET || 'troque_esta_chave';

function init(){
  db.serialize(()=>{
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT, email TEXT UNIQUE, password TEXT, role TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT, description TEXT, reward REAL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER, user_id INTEGER, evidence TEXT, status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(task_id) REFERENCES tasks(id), FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
  });
}
init();

// Helpers
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({message:'Sem token'});
  const token = h.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, payload)=>{
    if(err) return res.status(401).json({message:'Token inválido'});
    req.user = payload;
    next();
  });
}

// Routes
app.get('/api/tasks', (req,res)=>{
  db.all('SELECT * FROM tasks ORDER BY created_at DESC', [], (err, rows)=>{
    if(err) return res.status(500).json({message:err.message});
    res.json(rows);
  });
});

app.post('/api/tasks', authMiddleware, (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({message:'Apenas admin'});
  const {title,description,reward} = req.body;
  db.run('INSERT INTO tasks(title,description,reward) VALUES(?,?,?)', [title,description,reward], function(err){
    if(err) return res.status(500).json({message:err.message});
    res.json({message:'Tarefa publicada', id:this.lastID});
  });
});

// Auth
app.post('/api/auth/register', async (req,res)=>{
  const {name,email,password,role} = req.body;
  if(!email||!password) return res.status(400).json({message:'Email e senha obrigatórios'});
  const hashed = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)', [name,email,hashed,role||'worker'], function(err){
    if(err) return res.status(400).json({message:err.message});
    res.json({message:'Usuário criado'});
  });
});

app.post('/api/auth/login', (req,res)=>{
  const {email,password} = req.body;
  if(!email||!password) return res.status(400).json({message:'Email e senha obrigatórios'});
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err,user)=>{
    if(err) return res.status(500).json({message:err.message});
    if(!user) return res.status(400).json({message:'Usuário não encontrado'});
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({message:'Senha incorreta'});
    const token = jwt.sign({id:user.id,email:user.email,role:user.role,name:user.name}, JWT_SECRET, {expiresIn:'7d'});
    res.json({token});
  });
});

// Submissions
app.post('/api/submissions', authMiddleware, (req,res)=>{
  const {taskId, evidence} = req.body;
  db.run('INSERT INTO submissions(task_id,user_id,evidence) VALUES(?,?,?)', [taskId, req.user.id, evidence], function(err){
    if(err) return res.status(500).json({message:err.message});
    res.json({message:'Submissão criada', id:this.lastID});
  });
});

app.get('/api/submissions', authMiddleware, (req,res)=>{
  // admin gets all, others get all pending for admin visibility or their own
  if(req.user.role === 'admin'){
    db.all(`SELECT s.*, t.title as task_title, u.name as user_name FROM submissions s
      LEFT JOIN tasks t ON t.id = s.task_id
      LEFT JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC`, [], (err,rows)=>{
        if(err) return res.status(500).json({message:err.message});
        res.json(rows);
      });
  } else {
    db.all(`SELECT s.*, t.title as task_title FROM submissions s
      LEFT JOIN tasks t ON t.id = s.task_id WHERE s.user_id = ? ORDER BY s.created_at DESC`, [req.user.id], (err,rows)=>{
        if(err) return res.status(500).json({message:err.message});
        res.json(rows);
      });
  }
});

app.get('/api/submissions/mine', authMiddleware, (req,res)=>{
  db.all(`SELECT s.*, t.title as task_title FROM submissions s
    LEFT JOIN tasks t ON t.id = s.task_id WHERE s.user_id = ? ORDER BY s.created_at DESC`, [req.user.id], (err,rows)=>{
      if(err) return res.status(500).json({message:err.message});
      res.json(rows);
    });
});

app.put('/api/submissions/:id', authMiddleware, (req,res)=>{
  if(req.user.role !== 'admin') return res.status(403).json({message:'Apenas admin'});
  const id = req.params.id;
  const {status} = req.body;
  db.run('UPDATE submissions SET status=? WHERE id=?', [status,id], function(err){
    if(err) return res.status(500).json({message:err.message});
    res.json({message:'Status atualizado'});
  });
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Server running on port',PORT));
