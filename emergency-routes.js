// Route d'urgence pour créer un admin
// PROTECTION : nécessite la variable d'environnement SETUP_SECRET
module.exports = function(app, db, bcrypt) {

  app.get('/api/emergency-setup', async (req, res) => {
    // Vérification du secret
    const setupSecret = process.env.SETUP_SECRET;
    if (!setupSecret || req.query.secret !== setupSecret) {
      return res.status(403).send('<h1>403 Accès refusé</h1><p>Définissez SETUP_SECRET dans les variables d\'environnement Railway et passez ?secret=VOTRE_SECRET dans l\'URL.</p>');
    }

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
        `, (err) => { if (err) reject(err); else resolve(); });
      });

      // 2. Supprimer l'ancien admin s'il existe
      await new Promise((resolve) => {
        db.db.run(`DELETE FROM users WHERE username = 'admin'`, () => resolve());
      });

      // 3. Créer le nouvel admin avec bcrypt
      const hashedPassword = bcrypt.hashSync('admin123', 10);

      await new Promise((resolve, reject) => {
        db.db.run(
          `INSERT INTO users (username, password, role, fullName) VALUES (?, ?, ?, ?)`,
          ['admin', hashedPassword, 'admin', 'Administrateur'],
          function(err) { if (err) reject(err); else resolve({ id: this.lastID }); }
        );
      });

      // 4. Vérifier
      const user = await new Promise((resolve, reject) => {
        db.db.get(`SELECT id, username, role FROM users WHERE username = 'admin'`, (err, row) => {
          if (err) reject(err); else resolve(row);
        });
      });

      res.send(`
        <h1>✅ Admin créé avec succès !</h1>
        <p><strong>Username:</strong> ${user.username}</p>
        <p><strong>Password:</strong> admin123</p>
        <p><em>Changez le mot de passe après connexion.</em></p>
        <br>
        <a href="/login.html" style="font-size: 20px; color: #d35400;">→ Connexion</a>
      `);

    } catch (error) {
      res.status(500).send(`<h1>❌ Erreur</h1><p>${error.message}</p>`);
    }
  });
};
