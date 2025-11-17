// Initialize DB with an admin user (password: admin123)
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname,'microtasks.db'));
async function init(){
  db.serialize(async ()=>{
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT)`);
    const hashed = await bcrypt.hash('admin123',10);
    db.run('INSERT OR IGNORE INTO users(name,email,password,role) VALUES(?,?,?,?)',['Admin','admin@microtask.local',hashed,'admin']);
    console.log('DB inicializado. Usuário admin criado: admin@microtask.local / admin123');
    db.close();
  });
}
init();
