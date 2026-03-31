// Route d'urgence pour créer un admin - VERSION SIMPLIFIÉE
module.exports = function(app, db, bcrypt) {
  
  app.get('/api/emergency-setup', async (req, res) => {
    try {
      // 1. Créer la table users si elle n'existe pas
      await new Promise((resolve, reject) => {
        db.db.run(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            fullName TEXT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
          )
        `, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      // 2. Supprimer l'ancien admin s'il existe
      await new Promise((resolve) => {
        db.db.run(`DELETE FROM users WHERE username = 'admin'`, () => resolve());
      });
      
      // 3. Créer le nouvel admin avec bcrypt
      const hashedPassword = bcrypt.hashSync('admin123', 10);
      
      const result = await new Promise((resolve, reject) => {
        db.db.run(
          `INSERT INTO users (username, password, role, fullName) VALUES (?, ?, ?, ?)`,
          ['admin', hashedPassword, 'admin', 'Administrateur'],
          function(err) {
            if (err) reject(err);
            else resolve({ id: this.lastID });
          }
        );
      });
      
      // 4. Vérifier que ça marche
      const user = await new Promise((resolve, reject) => {
        db.db.get(`SELECT id, username, role FROM users WHERE username = 'admin'`, (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
      
      res.send(`
        <h1>✅ Admin créé avec succès !</h1>
        <p><strong>ID:</strong> ${user.id}</p>
        <p><strong>Username:</strong> ${user.username}</p>
        <p><strong>Password:</strong> admin123</p>
        <p><strong>Role:</strong> ${user.role}</p>
        <br>
        <a href="/login.html" style="font-size: 20px; color: #d35400;">
          → Aller à la page de connexion
        </a>
      `);
      
    } catch (error) {
      res.status(500).send(`
        <h1>❌ Erreur</h1>
        <p>${error.message}</p>
        <pre>${error.stack}</pre>
      `);
    }
  });

  // Route test de login
  app.post('/api/test-login', async (req, res) => {
    try {
      const { username, password } = req.body;
      
      const user = await new Promise((resolve, reject) => {
        db.db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
      
      if (!user) {
        return res.json({ success: false, error: 'Utilisateur non trouvé' });
      }
      
      const valid = bcrypt.compareSync(password, user.password);
      
      res.json({
        success: valid,
        userFound: !!user,
        passwordMatch: valid,
        user: valid ? { id: user.id, username: user.username, role: user.role } : null
      });
      
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
};
