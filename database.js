const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

class Database {
  constructor() {
    // Utiliser le volume persistant sur Render, sinon le dossier local
    const dbPath = process.env.RENDER_DISK_PATH || __dirname;
    this.db = new sqlite3.Database(path.join(dbPath, 'transfers.db'));
    this.init();
  }

  init() {
    // Table des utilisateurs (admin/opérateur)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'operator',
        fullName TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) console.error('Error creating users table:', err.message);
    });

    // Table des chauffeurs (profils)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS drivers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        carName TEXT,
        email TEXT,
        language TEXT DEFAULT 'fr',
        status TEXT DEFAULT 'active',
        isBusy INTEGER DEFAULT 0,
        rating REAL DEFAULT 5.0,
        totalTransfers INTEGER DEFAULT 0,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Migration: Add clientRating column to transfers
    this.db.run(`ALTER TABLE transfers ADD COLUMN clientRating INTEGER DEFAULT NULL`, (err) => {
      if (err) console.log('Migration clientRating:', err.message);
    });

    // Migration: Add carName column if not exists (for existing databases)
    this.db.run(`ALTER TABLE drivers ADD COLUMN carName TEXT`, (err) => {
      if (err) console.log('Migration carName:', err.message);
    });
    // Migration: Add isBusy column if not exists
    this.db.run(`ALTER TABLE drivers ADD COLUMN isBusy INTEGER DEFAULT 0`, (err) => {
      if (err) console.log('Migration isBusy:', err.message);
    });

    // Table des clients
    this.db.run(`
      CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table des transferts (mise à jour)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        clientId INTEGER,
        clientName TEXT NOT NULL,
        clientPhone TEXT,
        pickupDateTime TEXT NOT NULL,
        pickupLocation TEXT NOT NULL,
        destination TEXT NOT NULL,
        driverId INTEGER,
        driverName TEXT NOT NULL,
        driverPhone TEXT NOT NULL,
        language TEXT DEFAULT 'fr',
        status TEXT DEFAULT 'pending',
        callReminderSent INTEGER DEFAULT 0,
        whatsappReminderSent INTEGER DEFAULT 0,
        alertSent INTEGER DEFAULT 0,
        clientNotified INTEGER DEFAULT 0,
        trackingToken TEXT UNIQUE,
        createdBy INTEGER,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (driverId) REFERENCES drivers(id),
        FOREIGN KEY (clientId) REFERENCES clients(id),
        FOREIGN KEY (createdBy) REFERENCES users(id)
      )
    `);

    // Table des logs d'audit
    this.db.run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        action TEXT NOT NULL,
        entityType TEXT,
        entityId INTEGER,
        details TEXT,
        ipAddress TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);

    // Créer l'admin par défaut (password: admin123)
    this.createDefaultAdmin();
  }

  async createDefaultAdmin() {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    this.db.run(
      `INSERT OR IGNORE INTO users (username, password, role, fullName) VALUES (?, ?, ?, ?)`,
      ['admin', hashedPassword, 'admin', 'Administrateur']
    );
  }

  // ========== USERS ==========
  async createUser(user) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO users (username, password, role, fullName) VALUES (?, ?, ?, ?)`,
        [user.username, hashedPassword, user.role || 'operator', user.fullName],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID, ...user });
        }
      );
    });
  }

  async getUserByUsername(username) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  async validatePassword(user, password) {
    return bcrypt.compare(password, user.password);
  }

  // Mettre à jour un utilisateur
  updateUser(id, updates) {
    return new Promise((resolve, reject) => {
      const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
      const values = [...Object.values(updates), id];
      this.db.run(
        `UPDATE users SET ${fields} WHERE id = ?`,
        values,
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  // Récupérer tous les utilisateurs
  getAllUsers() {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT id, username, role, fullName, createdAt FROM users ORDER BY id`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  // Supprimer un utilisateur
  deleteUser(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `DELETE FROM users WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  // ========== DRIVERS ==========
  createDriver(driver) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO drivers (name, phone, carName, email, language) VALUES (?, ?, ?, ?, ?)`,
        [driver.name, driver.phone, driver.carName, driver.email, driver.language || 'fr'],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID, ...driver });
        }
      );
    });
  }

  getAllDrivers() {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT *, isBusy as is_busy FROM drivers ORDER BY name`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getActiveDrivers() {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT * FROM drivers WHERE status = 'active' ORDER BY name`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getDriverById(id) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT * FROM drivers WHERE id = ?`,
        [id],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  updateDriver(id, updates) {
    return new Promise((resolve, reject) => {
      const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
      const values = [...Object.values(updates), id];
      this.db.run(
        `UPDATE drivers SET ${fields} WHERE id = ?`,
        values,
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  deleteDriver(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `DELETE FROM drivers WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  incrementDriverTransfers(driverId) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE drivers SET totalTransfers = totalTransfers + 1 WHERE id = ?`,
        [driverId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  // ========== CLIENTS ==========
  createClient(client) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO clients (name, phone, email) VALUES (?, ?, ?)`,
        [client.name, client.phone, client.email],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID, ...client });
        }
      );
    });
  }

  getOrCreateClient(client) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT * FROM clients WHERE phone = ?`,
        [client.phone],
        (err, row) => {
          if (err) reject(err);
          else if (row) resolve(row);
          else {
            this.createClient(client).then(resolve).catch(reject);
          }
        }
      );
    });
  }

  // ========== TRANSFERS ==========
  async createTransfer(transfer, userId) {
    const token = require('crypto').randomBytes(16).toString('hex');
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO transfers (clientId, clientName, clientPhone, pickupDateTime, pickupLocation, destination, driverId, driverName, driverPhone, language, trackingToken, createdBy, status) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [transfer.clientId, transfer.clientName, transfer.clientPhone, transfer.pickupDateTime, transfer.pickupLocation, transfer.destination, transfer.driverId, transfer.driverName, transfer.driverPhone, transfer.language || 'fr', token, userId, transfer.status || 'pending'],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID, trackingToken: token, ...transfer });
        }
      );
    });
  }

  getAllTransfers(limit = 100) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT t.*, d.name as driverFullName, d.rating 
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id
         ORDER BY t.pickupDateTime DESC 
         LIMIT ?`,
        [limit],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getTransfersByStatus(status) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT t.*, d.name as driverFullName, d.rating 
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id
         WHERE t.status = ? 
         ORDER BY t.pickupDateTime DESC`,
        [status],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getTransferById(id) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT t.*, d.name as driverFullName, d.rating, u.username as createdByUser
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id
         LEFT JOIN users u ON t.createdBy = u.id
         WHERE t.id = ?`,
        [id],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  getTransferByToken(token) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT t.*, d.name as driverFullName
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id
         WHERE t.trackingToken = ?`,
        [token],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  getCompletedTransferByClientPhone(phone) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT * FROM transfers WHERE clientPhone = ? AND status = 'completed' AND clientRating IS NULL ORDER BY pickupDateTime DESC LIMIT 1`,
        [phone],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  updateTransferRating(id, rating) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET clientRating = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
        [rating, id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  getTransferByDriverPhone(phone) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT * FROM transfers WHERE driverPhone = ? AND status IN ('pending', 'assigned') ORDER BY pickupDateTime ASC LIMIT 1`,
        [phone],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  getTransfersByPhone(phone) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT t.*, d.name as driver_name, d.phone as driver_phone, t.trackingToken as tracking_token
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id 
         WHERE t.clientPhone = ? 
         ORDER BY t.pickupDateTime DESC 
         LIMIT 10`,
        [phone],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  updateTransfer(id, updates) {
    return new Promise((resolve, reject) => {
      const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
      const values = [...Object.values(updates), id];
      this.db.run(
        `UPDATE transfers SET ${fields}, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
        values,
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  updateTransferStatus(id, status) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET status = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
        [status, id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  cancelTransfer(id, reason) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET status = 'cancelled', updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else {
            this.logAudit(null, 'CANCEL_TRANSFER', 'transfer', id, { reason });
            resolve();
          }
        }
      );
    });
  }

  searchTransfers(query) {
    return new Promise((resolve, reject) => {
      const search = `%${query}%`;
      this.db.all(
        `SELECT t.*, d.name as driverFullName 
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id
         WHERE t.clientName LIKE ? OR t.driverName LIKE ? OR t.pickupLocation LIKE ? OR t.destination LIKE ?
         ORDER BY t.pickupDateTime DESC 
         LIMIT 50`,
        [search, search, search, search],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getTransfersForExport(startDate, endDate) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT t.*, d.name as driverFullName, u.username as createdByUser
         FROM transfers t 
         LEFT JOIN drivers d ON t.driverId = d.id
         LEFT JOIN users u ON t.createdBy = u.id
         WHERE date(t.pickupDateTime) >= date(?) AND date(t.pickupDateTime) <= date(?)
         ORDER BY t.pickupDateTime DESC`,
        [startDate, endDate],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  // ========== SCHEDULER ==========
  getPendingTransfersNeedingCall() {
    const twoHoursFromNow = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    const twoHoursAgo = new Date(Date.now() + 2 * 60 * 60 * 1000 - 5 * 60 * 1000).toISOString();
    
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT * FROM transfers 
         WHERE status IN ('pending', 'assigned') 
         AND callReminderSent = 0
         AND pickupDateTime <= ?
         AND pickupDateTime >= ?`,
        [twoHoursFromNow, twoHoursAgo],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getPendingTransfersNeedingWhatsApp() {
    const oneHourFromNow = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT * FROM transfers 
         WHERE status IN ('pending', 'assigned') 
         AND callReminderSent = 1
         AND whatsappReminderSent = 0
         AND pickupDateTime <= ?`,
        [oneHourFromNow],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getPendingTransfersNeedingAlert() {
    const thirtyMinFromNow = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT * FROM transfers 
         WHERE status IN ('pending', 'assigned') 
         AND whatsappReminderSent = 1
         AND alertSent = 0
         AND pickupDateTime <= ?`,
        [thirtyMinFromNow],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getTransfersNeedingClientNotification() {
    const twentyFourHoursFromNow = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT * FROM transfers 
         WHERE clientPhone IS NOT NULL 
         AND clientNotified = 0
         AND pickupDateTime <= ?`,
        [twentyFourHoursFromNow],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  markCallReminderSent(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET callReminderSent = 1 WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  markWhatsAppReminderSent(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET whatsappReminderSent = 1 WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  markAlertSent(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET alertSent = 1 WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  markClientNotified(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE transfers SET clientNotified = 1 WHERE id = ?`,
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  // ========== STATISTIQUES ==========
  getStats(startDate, endDate) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN status = 'confirmed' OR status = 'confirmed_by_call' THEN 1 ELSE 0 END) as confirmed,
          SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled,
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
          SUM(CASE WHEN alertSent = 1 THEN 1 ELSE 0 END) as alerts
         FROM transfers 
         WHERE date(pickupDateTime) >= date(?) AND date(pickupDateTime) <= date(?)`,
        [startDate, endDate],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows[0]);
        }
      );
    });
  }

  getTopDrivers(limit = 10) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT 
          d.name,
          d.totalTransfers,
          d.rating,
          COUNT(t.id) as recentTransfers,
          SUM(CASE WHEN t.status = 'confirmed' OR t.status = 'confirmed_by_call' THEN 1 ELSE 0 END) as confirmedCount
         FROM drivers d
         LEFT JOIN transfers t ON d.id = t.driverId AND t.pickupDateTime >= date('now', '-30 days')
         GROUP BY d.id
         ORDER BY recentTransfers DESC
         LIMIT ?`,
        [limit],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getDailyStats(days = 30) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT 
          date(pickupDateTime) as date,
          COUNT(*) as total,
          SUM(CASE WHEN status = 'confirmed' OR status = 'confirmed_by_call' THEN 1 ELSE 0 END) as confirmed
         FROM transfers 
         WHERE pickupDateTime >= date('now', '-${days} days')
         GROUP BY date(pickupDateTime)
         ORDER BY date DESC`,
        [],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  // ========== AUDIT LOGS ==========
  logAudit(userId, action, entityType, entityId, details) {
    return new Promise((resolve, reject) => {
      this.db.run(
        `INSERT INTO audit_logs (userId, action, entityType, entityId, details) VALUES (?, ?, ?, ?, ?)`,
        [userId, action, entityType, entityId, JSON.stringify(details)],
        function(err) {
          if (err) reject(err);
          else resolve({ id: this.lastID });
        }
      );
    });
  }

  getAuditLogs(limit = 100) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT l.*, u.username 
         FROM audit_logs l 
         LEFT JOIN users u ON l.userId = u.id
         ORDER BY l.createdAt DESC 
         LIMIT ?`,
        [limit],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  // ========== DEFAULT ADMIN ==========
  async createDefaultAdmin() {
    try {
      // Vérifier si un admin existe déjà
      const admin = await this.getUserByUsername('admin');
      if (!admin) {
        // Créer admin par défaut
        const hashedPassword = bcrypt.hashSync('admin123', 10);
        await this.createUser({
          username: 'admin',
          password: hashedPassword,
          role: 'admin',
          fullName: 'Administrateur'
        });
        console.log('✅ Admin par défaut créé: admin / admin123');
      }
    } catch (err) {
      console.error('Erreur création admin:', err.message);
    }
  }

  // ========== BACKUP ==========
  backup() {
    const fs = require('fs');
    const dbPath = process.env.RENDER_DISK_PATH || __dirname;
    const backupsDir = path.join(__dirname, 'backups');
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true });
    }
    const backupPath = path.join(backupsDir, `transfers_backup_${Date.now()}.db`);
    const sourcePath = path.join(dbPath, 'transfers.db');
    return new Promise((resolve, reject) => {
      try {
        fs.copyFileSync(sourcePath, backupPath);
        resolve(backupPath);
      } catch (err) {
        reject(err);
      }
    });
  }
}

module.exports = Database;
