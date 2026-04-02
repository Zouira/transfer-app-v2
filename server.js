require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const https = require('https');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('./database');
const TwilioService = require('./twilio');
const Scheduler = require('./scheduler');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'transfer-secret-key';

// ========== SECURITY HEADERS ==========
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ========== RATE LIMITING ==========
const _rlStore = new Map();
setInterval(() => {
  const cutoff = Date.now() - 3600000;
  for (const [k, v] of _rlStore.entries()) {
    const f = v.filter(t => t > cutoff);
    if (f.length === 0) _rlStore.delete(k); else _rlStore.set(k, f);
  }
}, 600000);

function makeRateLimit(windowMs, max, message) {
  return (req, res, next) => {
    const key = (req.ip || '') + req.path;
    const now = Date.now();
    const hits = (_rlStore.get(key) || []).filter(t => t > now - windowMs);
    hits.push(now);
    _rlStore.set(key, hits);
    if (hits.length > max) {
      return res.status(429).json({ success: false, error: message || 'Trop de requêtes. Réessayez plus tard.' });
    }
    next();
  };
}

const loginLimiter   = makeRateLimit(15 * 60000, 10, 'Trop de tentatives. Réessayez dans 15 minutes.');
const publicLimiter  = makeRateLimit(60000, 30, 'Trop de requêtes. Réessayez dans une minute.');

// Apply rate limiters before route definitions
app.use('/api/auth/login',       loginLimiter);
app.use('/api/transfers/lookup', publicLimiter);
app.use('/api/track',            publicLimiter);

// ========== TWILIO WEBHOOK VALIDATION ==========
const validateTwilioSignature = (req, res, next) => {
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  if (!authToken) return next(); // skip if not configured
  const signature = req.headers['x-twilio-signature'];
  if (!signature) {
    console.warn('Webhook sans signature Twilio rejeté depuis:', req.ip);
    return res.status(403).send('<Response></Response>');
  }
  const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
  const url = `${baseUrl}/webhook/whatsapp`;
  try {
    const twilioLib = require('twilio');
    if (!twilioLib.validateRequest(authToken, signature, url, req.body)) {
      console.warn('Signature Twilio invalide depuis:', req.ip);
      return res.status(403).send('<Response></Response>');
    }
  } catch(e) {
    console.error('Erreur validation Twilio:', e.message);
  }
  next();
};

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, error: 'Token requis' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Token invalide' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Accès admin requis' });
  }
  next();
};

// Admin ou Directeur (lecture seule — pas d'export CSV ni gestion utilisateurs)
const requireAdminOrDirecteur = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'directeur') {
    return res.status(403).json({ success: false, error: 'Accès réservé aux administrateurs et directeurs' });
  }
  next();
};

// Initialize services
const db = new Database();
const twilio = new TwilioService();
const scheduler = new Scheduler(db, twilio);

// Démarrer le scheduler
scheduler.start();

// ========== ROUTES AUTHENTIFICATION ==========

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.getUserByUsername(username);
    
    if (!user || !(await db.validatePassword(user, password))) {
      return res.status(401).json({ success: false, error: 'Identifiants invalides' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, fullName: user.fullName },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await db.logAudit(user.id, 'LOGIN', 'user', user.id, { ip: req.ip });

    res.json({ 
      success: true, 
      token,
      user: { id: user.id, username: user.username, role: user.role, fullName: user.fullName }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Vérifier token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// Changer mot de passe (tout utilisateur connecté)
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, error: 'Mot de passe actuel et nouveau requis' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Nouveau mot de passe trop court (min 6 caractères)' });
    }
    const user = await db.getUserById(req.user.id);
    if (!user) return res.status(404).json({ success: false, error: 'Utilisateur introuvable' });

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'Mot de passe actuel incorrect' });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    await db.updateUserPassword(req.user.id, hashed);
    await db.logAudit(req.user.id, 'CHANGE_PASSWORD', 'user', req.user.id, {});
    res.json({ success: true, message: 'Mot de passe modifié avec succès ✅' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Route pour créer un admin (setup initial) — protégée par SETUP_SECRET
app.post('/api/setup-admin', async (req, res) => {
  try {
    const setupSecret = process.env.SETUP_SECRET;
    if (setupSecret && req.body.secret !== setupSecret) {
      return res.status(403).json({ success: false, error: 'Accès refusé — SETUP_SECRET requis' });
    }
    const { username, password } = req.body;
    const actualUsername = username || 'admin';
    const actualPassword = password || 'admin123';
    
    console.log('Setup admin demandé pour:', actualUsername);
    
    // Hash synchrone avec bcrypt
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(actualPassword, salt);
    
    console.log('Hash généré:', hashedPassword);
    
    // Vérifier si l'utilisateur existe déjà
    let existingUser;
    try {
      existingUser = await db.getUserByUsername(actualUsername);
      console.log('Utilisateur existant:', existingUser ? 'OUI' : 'NON');
    } catch (e) {
      console.log('Erreur getUserByUsername:', e.message);
      existingUser = null;
    }
    
    if (existingUser) {
      // Supprimer et recréer pour être sûr
      console.log('Suppression admin existant...');
      await db.deleteUser(existingUser.id);
    }
    
    // Créer un nouvel admin
    console.log('Création nouvel admin...');
    const user = await db.createUser({
      username: actualUsername,
      password: hashedPassword,
      role: 'admin',
      fullName: 'Administrateur'
    });
    
    console.log('✅ Admin créé:', actualUsername);
    res.json({ 
      success: true, 
      message: 'Admin créé avec succès', 
      user: { id: user.id, username: actualUsername },
      password: actualPassword,
      hash: hashedPassword
    });
  } catch (error) {
    console.error('❌ Erreur setup admin:', error);
    res.status(500).json({ success: false, error: error.message, stack: error.stack });
  }
});

// Route de debug - vérifier l'état (admin uniquement)
app.get('/api/debug/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.getAllUsers();
    res.json({
      success: true,
      count: users.length,
      users: users.map(u => ({ id: u.id, username: u.username, role: u.role }))
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Route pour réparer la base de données (créer les tables manquantes)
app.post('/api/fix-database', async (req, res) => {
  try {
    console.log('🔧 Réparation de la base de données demandée...');
    
    // Forcer la création de la table users
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
    
    // Vérifier les tables existantes
    const tables = await new Promise((resolve, reject) => {
      db.db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, rows) => {
        if (err) reject(err);
        else resolve(rows.map(r => r.name));
      });
    });
    
    console.log('✅ Tables existantes:', tables);
    
    res.json({ 
      success: true, 
      message: 'Base de données réparée',
      tables: tables
    });
  } catch (error) {
    console.error('❌ Erreur réparation DB:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Lister les utilisateurs (admin + directeur)
app.get('/api/users', authenticateToken, requireAdminOrDirecteur, async (req, res) => {
  try {
    const users = await db.getAllUsers();
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Créer utilisateur (admin: tous les rôles — directeur: opérateur uniquement)
app.post('/api/users', authenticateToken, requireAdminOrDirecteur, async (req, res) => {
  try {
    const requestedRole = req.body.role || 'operator';
    if (req.user.role === 'directeur' && requestedRole !== 'operator') {
      return res.status(403).json({ success: false, error: 'Le directeur ne peut créer que des opérateurs' });
    }
    const user = await db.createUser(req.body);
    await db.logAudit(req.user.id, 'CREATE_USER', 'user', user.id, { username: req.body.username });
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Supprimer utilisateur (admin uniquement)
app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.user.id) {
      return res.status(400).json({ success: false, error: 'Impossible de supprimer votre propre compte' });
    }
    await db.deleteUser(req.params.id);
    await db.logAudit(req.user.id, 'DELETE_USER', 'user', req.params.id, {});
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== ROUTES CHAUFFEURS ==========

// Liste des chauffeurs
app.get('/api/drivers', authenticateToken, async (req, res) => {
  try {
    const drivers = await db.getAllDrivers();
    res.json({ success: true, drivers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Chauffeurs actifs
app.get('/api/drivers/active', authenticateToken, async (req, res) => {
  try {
    const drivers = await db.getActiveDrivers();
    res.json({ success: true, drivers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Créer chauffeur (ou mettre à jour si le numéro existe déjà)
app.post('/api/drivers', authenticateToken, async (req, res) => {
  try {
    const { name, carName, email, language } = req.body;
    // Normaliser le numéro : retirer espaces, convertir 06.../07... en +2126.../+2127...
    const phone = (req.body.phone || '').replace(/\s/g, '').replace(/^0([67])/, '+2126$1').replace(/^00212/, '+212');

    // Vérifier si un chauffeur avec ce numéro existe déjà
    const existingDriver = await db.getAllDrivers().then(drivers =>
      drivers.find(d => d.phone === phone)
    );
    
    if (existingDriver) {
      // Mettre à jour le chauffeur existant
      await db.updateDriver(existingDriver.id, { name, phone, carName, email, language });
      await db.logAudit(req.user.id, 'UPDATE_DRIVER', 'driver', existingDriver.id, { name });
      res.json({ success: true, driver: { ...existingDriver, name, phone, carName, email, language }, updated: true });
    } else {
      // Créer un nouveau chauffeur
      const driver = await db.createDriver(req.body);
      await db.logAudit(req.user.id, 'CREATE_DRIVER', 'driver', driver.id, { name: driver.name });
      res.json({ success: true, driver });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Modifier chauffeur
app.put('/api/drivers/:id', authenticateToken, async (req, res) => {
  try {
    await db.updateDriver(req.params.id, req.body);
    await db.logAudit(req.user.id, 'UPDATE_DRIVER', 'driver', req.params.id, req.body);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Supprimer chauffeur
app.delete('/api/drivers/:id', authenticateToken, async (req, res) => {
  try {
    await db.deleteDriver(req.params.id);
    await db.logAudit(req.user.id, 'DELETE_DRIVER', 'driver', req.params.id, {});
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== ROUTES TRANSFERTS ==========

// Créer un transfert
app.post('/api/transfers', authenticateToken, async (req, res) => {
  try {
    const { 
      clientName, client_name,
      clientPhone, client_phone,
      pickupDateTime, pickup_time,
      pickupLocation, pickup_location,
      destination,
      driverId, driver_id,
      language,
      notes
    } = req.body;
    
    // Support both camelCase and snake_case
    const actualClientName = clientName || client_name;
    const actualClientPhone = clientPhone || client_phone;
    const actualPickupTime = pickupDateTime || pickup_time;
    const actualPickupLocation = pickupLocation || pickup_location;
    const actualDriverId = driverId || driver_id;
    
    if (!actualDriverId) {
      return res.status(400).json({ success: false, error: 'ID du chauffeur requis' });
    }
    
    // Récupérer info chauffeur
    const driver = await db.getDriverById(actualDriverId);
    if (!driver) {
      return res.status(400).json({ success: false, error: 'Chauffeur non trouvé' });
    }

    // Créer ou récupérer client
    let client = null;
    if (actualClientPhone) {
      client = await db.getOrCreateClient({ name: actualClientName, phone: actualClientPhone });
    }

    const transfer = await db.createTransfer({
      clientId: client?.id,
      clientName: actualClientName,
      clientPhone: actualClientPhone,
      pickupDateTime: actualPickupTime,
      pickupLocation: actualPickupLocation,
      destination,
      driverId: driver.id,
      driverName: driver.name,
      driverPhone: driver.phone,
      language: language || driver.language || 'fr'
    }, req.user.id);

    // Envoyer notification WhatsApp au chauffeur (non-bloquant)
    const messages = {
      fr: `🚗 Nouveau transfert assigné:\n` +
          `👤 Client: ${actualClientName}\n` +
          `🕐 Date/Heure: ${actualPickupTime}\n` +
          `📍 Départ: ${actualPickupLocation}\n` +
          `🏁 Destination: ${destination}\n\n` +
          `Répondez OK pour confirmer la réception.`,
      ar: `🚗 نقل جديد تم تعيينه:\n` +
          `👤 العميل: ${actualClientName}\n` +
          `🕐 التاريخ/الوقت: ${actualPickupTime}\n` +
          `📍 الانطلاق: ${actualPickupLocation}\n` +
          `🏁 الوجهة: ${destination}\n\n` +
          `الرد بـ OK لتأكيد الاستلام.`
    };

    twilio.sendWhatsApp(driver.phone, messages[language || driver.language || 'fr'])
      .catch(err => console.error('WhatsApp chauffeur (non-bloquant):', err.message));

    // Incrémenter compteur chauffeur
    await db.incrementDriverTransfers(driver.id);

    await db.logAudit(req.user.id, 'CREATE_TRANSFER', 'transfer', transfer.id, { 
      clientName, driverName: driver.name, pickupDateTime 
    });

    res.json({ success: true, transfer });
  } catch (error) {
    console.error('Error creating transfer:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Liste des transferts
app.get('/api/transfers', authenticateToken, async (req, res) => {
  try {
    const { status, limit } = req.query;
    let transfers;
    
    if (status) {
      transfers = await db.getTransfersByStatus(status);
    } else {
      transfers = await db.getAllTransfers(parseInt(limit) || 100);
    }
    
    res.json({ success: true, transfers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Rechercher transferts
app.get('/api/transfers/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.status(400).json({ success: false, error: 'Query requise' });
    }
    const transfers = await db.searchTransfers(q);
    res.json({ success: true, transfers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Recherche par téléphone (public - pour track.html)
app.get('/api/transfers/lookup', async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) {
      return res.status(400).json({ success: false, error: 'Téléphone requis' });
    }
    const transfers = await db.getTransfersByPhone(phone);
    res.json({ success: true, transfers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Détails d'un transfert
app.get('/api/transfers/:id', authenticateToken, async (req, res) => {
  try {
    const transfer = await db.getTransferById(req.params.id);
    if (!transfer) {
      return res.status(404).json({ success: false, error: 'Transfert non trouvé' });
    }
    res.json({ success: true, transfer });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Modifier un transfert
app.put('/api/transfers/:id', authenticateToken, async (req, res) => {
  try {
    const transfer = await db.getTransferById(req.params.id);
    if (!transfer) {
      return res.status(404).json({ success: false, error: 'Transfert non trouvé' });
    }

    if (transfer.status === 'cancelled') {
      return res.status(400).json({ success: false, error: 'Transfert annulé - modification impossible' });
    }

    const updates = {};
    const allowedFields = ['clientName', 'clientPhone', 'pickupDateTime', 'pickupLocation', 'destination', 'driverId', 'language'];
    
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Si changement de chauffeur, récupérer ses infos
    if (updates.driverId && updates.driverId !== transfer.driverId) {
      const driver = await db.getDriverById(updates.driverId);
      if (!driver) {
        return res.status(400).json({ success: false, error: 'Chauffeur non trouvé' });
      }
      updates.driverName = driver.name;
      updates.driverPhone = driver.phone;
      
      // Notifier nouveau chauffeur
      const messages = {
        fr: `🚗 Transfert réassigné:\n` +
            `👤 Client: ${updates.clientName || transfer.clientName}\n` +
            `🕐 Date/Heure: ${updates.pickupDateTime || transfer.pickupDateTime}\n` +
            `📍 Départ: ${updates.pickupLocation || transfer.pickupLocation}\n` +
            `🏁 Destination: ${updates.destination || transfer.destination}\n\n` +
            `Répondez OK pour confirmer.`,
        ar: `🚗 تمت إعادة تعيين النقل:\n` +
            `👤 العميل: ${updates.clientName || transfer.clientName}\n` +
            `🕐 التاريخ/الوقت: ${updates.pickupDateTime || transfer.pickupDateTime}\n` +
            `📍 الانطلاق: ${updates.pickupLocation || transfer.pickupLocation}\n` +
            `🏁 الوجهة: ${updates.destination || transfer.destination}\n\n` +
            `الرد بـ OK للتأكيد.`
      };
      await twilio.sendWhatsApp(driver.phone, messages[updates.language || driver.language || 'fr']);
    }

    await db.updateTransfer(req.params.id, updates);
    await db.logAudit(req.user.id, 'UPDATE_TRANSFER', 'transfer', req.params.id, updates);

    res.json({ success: true });
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Démarrer une mission (in_progress) — déclenché manuellement ou par WhatsApp "GO"
app.post('/api/transfers/:id/start', authenticateToken, async (req, res) => {
  try {
    const transfer = await db.getTransferById(req.params.id);
    if (!transfer) return res.status(404).json({ success: false, error: 'Transfert non trouvé' });
    if (transfer.status === 'completed' || transfer.status === 'cancelled') {
      return res.status(400).json({ success: false, error: `Impossible — statut : ${transfer.status}` });
    }
    await db.updateTransferStatus(req.params.id, 'in_progress');
    await db.logAudit(req.user.id, 'START_TRANSFER', 'transfer', req.params.id, {});
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Terminer une mission (completed) — déclenché manuellement ou par WhatsApp "FIN"
app.post('/api/transfers/:id/complete', authenticateToken, async (req, res) => {
  try {
    const transfer = await db.getTransferById(req.params.id);
    if (!transfer) return res.status(404).json({ success: false, error: 'Transfert non trouvé' });
    if (transfer.status === 'cancelled') {
      return res.status(400).json({ success: false, error: 'Transfert annulé' });
    }
    await db.updateTransferStatus(req.params.id, 'completed');
    await db.logAudit(req.user.id, 'COMPLETE_TRANSFER', 'transfer', req.params.id, {});
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Annuler un transfert
app.post('/api/transfers/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const transfer = await db.getTransferById(req.params.id);
    if (!transfer) {
      return res.status(404).json({ success: false, error: 'Transfert non trouvé' });
    }

    const { reason } = req.body;
    
    // Notifier le chauffeur
    const messages = {
      fr: `❌ TRANSFERT ANNULÉ\n\n` +
          `Client: ${transfer.clientName}\n` +
          `Date: ${transfer.pickupDateTime}\n` +
          `${reason ? `Raison: ${reason}` : ''}`,
      ar: `❌ تم إلغاء النقل\n\n` +
          `العميل: ${transfer.clientName}\n` +
          `التاريخ: ${transfer.pickupDateTime}\n` +
          `${reason ? `السبب: ${reason}` : ''}`
    };
    
    await twilio.sendWhatsApp(transfer.driverPhone, messages[transfer.language || 'fr']);

    await db.cancelTransfer(req.params.id, reason);
    await db.logAudit(req.user.id, 'CANCEL_TRANSFER', 'transfer', req.params.id, { reason });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Mettre à jour le statut
app.post('/api/transfers/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    await db.updateTransferStatus(req.params.id, status);
    await db.logAudit(req.user.id, 'UPDATE_STATUS', 'transfer', req.params.id, { status });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Export CSV (admin + directeur)
app.get('/api/transfers/export/csv', authenticateToken, requireAdminOrDirecteur, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ success: false, error: 'Dates requises' });
    }

    const transfers = await db.getTransfersForExport(startDate, endDate);
    
    // Générer CSV
    const headers = ['ID', 'Date', 'Client', 'Téléphone', 'Départ', 'Destination', 'Chauffeur', 'Statut', 'Créé par'];
    const rows = transfers.map(t => [
      t.id,
      t.pickupDateTime,
      t.clientName,
      t.clientPhone || '',
      t.pickupLocation,
      t.destination,
      t.driverName,
      t.status,
      t.createdByUser || ''
    ]);

    const csv = [headers.join(','), ...rows.map(r => r.map(v => `"${(v || '').toString().replace(/"/g, '""')}"`).join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=transfers_${startDate}_${endDate}.csv`);
    res.send(csv);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== ROUTES STATISTIQUES ==========

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ success: false, error: 'Dates requises' });
    }

    const stats = await db.getStats(startDate, endDate);
    const topDrivers = await db.getTopDrivers(10);
    const dailyStats = await db.getDailyStats(30);

    res.json({ 
      success: true, 
      stats,
      topDrivers,
      dailyStats
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== ROUTES AUDIT ==========

app.get('/api/audit-logs', authenticateToken, requireAdminOrDirecteur, async (req, res) => {
  try {
    const logs = await db.getAuditLogs(100);
    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== WEBHOOKS TWILIO (pas besoin d'auth) ==========

// Geocoding proxy (évite CORS navigateur → Nominatim)
app.get('/api/geocode', publicLimiter, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 2 || q.length > 200) {
      return res.json({ lat: null, lon: null });
    }
    const searchQ = encodeURIComponent(q.trim() + ', Marrakech, Maroc');
    const data = await new Promise((resolve) => {
      https.get({
        hostname: 'nominatim.openstreetmap.org',
        path: `/search?q=${searchQ}&format=json&limit=1&countrycodes=ma`,
        headers: { 'User-Agent': 'TransferMarrakechApp/2.0', 'Accept-Language': 'fr' }
      }, (r) => {
        let body = '';
        r.on('data', c => body += c);
        r.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { resolve([]); } });
      }).on('error', () => resolve([]));
    });
    if (data && data.length > 0) {
      res.json({ lat: parseFloat(data[0].lat), lon: parseFloat(data[0].lon) });
    } else {
      res.json({ lat: null, lon: null });
    }
  } catch(e) {
    res.json({ lat: null, lon: null });
  }
});

// Webhook WhatsApp
app.post('/webhook/whatsapp', validateTwilioSignature, async (req, res) => {
  try {
    const { From, Body } = req.body;
    const phone = From.replace('whatsapp:', '');
    const bodyLower = (Body || '').toLowerCase().trim();
    const bodyClean = (Body || '').trim();

    // --- Messages du CHAUFFEUR ---
    const driverTransfer = await db.getTransferByDriverPhone(phone);
    if (driverTransfer) {
      const lang = driverTransfer.language || 'fr';

      if (bodyLower.includes('ok') && !['in_progress','completed','cancelled'].includes(driverTransfer.status)) {
        // Confirmation de réception
        await db.updateTransferStatus(driverTransfer.id, 'confirmed');
        await twilio.sendWhatsApp(phone, lang === 'ar' ? '✅ تم تأكيد النقل. شكراً!' : '✅ Transfert confirmé. Merci !');

      } else if (bodyLower === 'go' || bodyLower === 'parti' || bodyLower === 'départ' || bodyLower === 'depart') {
        // Mission démarrée
        await db.updateTransferStatus(driverTransfer.id, 'in_progress');
        await twilio.sendWhatsApp(phone, lang === 'ar' ? '🚗 تم تسجيل انطلاقك. بالتوفيق !' : '🚗 Mission démarrée. Bon voyage !');

      } else if (['planning', 'agenda', 'programme', 'courses', 'mes courses', 'planning?', 'agenda?'].includes(bodyLower) || bodyLower.startsWith('planning')) {
        // Récap du planning du jour
        const todayTransfers = await db.getTodayTransfersByDriverPhone(phone);
        let reply = '';
        if (!todayTransfers || todayTransfers.length === 0) {
          reply = `📅 Aucune course prévue pour aujourd'hui.\n\nBonne journée ! 😊`;
        } else {
          const dateStr = new Date().toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
          reply = `📅 Votre planning du ${dateStr} :\n\n`;
          todayTransfers.forEach((t, i) => {
            const time = new Date(t.pickupDateTime).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
            const statusEmoji = { pending: '⏳', confirmed: '✅', confirmed_by_call: '📞', in_progress: '🚗', completed: '🏁', cancelled: '❌' }[t.status] || '⏳';
            reply += `${i + 1}. ${statusEmoji} ${time}\n`;
            reply += `   👤 ${t.clientName}\n`;
            reply += `   📍 ${t.pickupLocation}\n`;
            reply += `   🏁 ${t.destination}\n`;
            if (i < todayTransfers.length - 1) reply += '\n';
          });
          reply += `\n\nTotal : ${todayTransfers.length} course(s) aujourd'hui.`;
        }
        await twilio.sendWhatsApp(phone, reply);

      } else if (bodyLower === 'fin' || bodyLower === 'arrivé' || bodyLower === 'arrive' || bodyLower === 'terminé' || bodyLower === 'termine') {
        // Mission terminée
        await db.updateTransferStatus(driverTransfer.id, 'completed');
        await twilio.sendWhatsApp(phone, lang === 'ar' ? '✅ تم تسجيل نهاية المهمة. شكراً !' : '✅ Mission terminée. Merci !');
      }

      res.send('<Response></Response>');
      return;
    }

    // --- Note du CLIENT (1-5) ---
    if (/^[1-5]$/.test(bodyClean)) {
      const clientTransfer = await db.getCompletedTransferByClientPhone(phone);
      if (clientTransfer) {
        const rating = parseInt(bodyClean);
        await db.updateTransferRating(clientTransfer.id, rating);
        await twilio.sendWhatsApp(phone, `⭐ Merci pour votre note de ${rating}/5 ! À très bientôt.`);
        const stars = '⭐'.repeat(rating);
        twilio.sendAlert(clientTransfer,
          `${stars} Avis client : ${rating}/5\nChauffeur : ${clientTransfer.driverName}\nTrajet : ${clientTransfer.pickupLocation} → ${clientTransfer.destination}`)
          .catch(err => console.error('Alert rating:', err.message));
      }
    }

    res.send('<Response></Response>');
  } catch (error) {
    console.error('Webhook error:', error);
    res.send('<Response></Response>');
  }
});

// Webhook appel vocal
app.post('/webhook/voice', async (req, res) => {
  const { To } = req.body;
  const transfer = await db.getTransferByDriverPhone(To);
  const lang = transfer?.language || 'fr';
  
  const voiceMessages = {
    fr: `
      <Response>
        <Say voice="woman" language="fr-FR">
          Bonjour, c'est le back-office Transfer Marrakech.
          Vous avez une course de nuit dans une heure trente.
          Appuyez sur 1 pour confirmer votre départ, ou sur 2 si vous avez un problème.
        </Say>
        <Gather numDigits="1" action="/webhook/voice/response" method="POST" timeout="10">
          <Say voice="woman" language="fr-FR">Appuyez sur 1 pour confirmer, ou 2 pour signaler un problème.</Say>
        </Gather>
        <Say voice="woman" language="fr-FR">Nous n'avons pas reçu de réponse. Veuillez consulter votre WhatsApp.</Say>
      </Response>
    `,
    ar: `
      <Response>
        <Say voice="woman" language="ar-SA">
          مرحباً، هذا مكتب ترانسفير مراكش.
          لديك رحلة ليلية خلال ساعة ونصف.
          اضغط 1 للتأكيد أنك ستنطلق، أو 2 إذا كان لديك مشكلة.
        </Say>
        <Gather numDigits="1" action="/webhook/voice/response" method="POST" timeout="10">
          <Say voice="woman" language="ar-SA">اضغط 1 للتأكيد، أو 2 لإبلاغ عن مشكلة.</Say>
        </Gather>
        <Say voice="woman" language="ar-SA">لم نتلق ردك. يرجى مراجعة واتساب.</Say>
      </Response>
    `
  };
  
  res.type('text/xml');
  res.send(voiceMessages[lang]);
});

app.post('/webhook/voice/response', async (req, res) => {
  const { Digits, From } = req.body;
  const transfer = await db.getTransferByDriverPhone(From);
  const lang = transfer?.language || 'fr';
  
  if (Digits === '1') {
    if (transfer) {
      await db.updateTransferStatus(transfer.id, 'confirmed_by_call');
    }
    
    const thankYouMessages = {
      fr: `
        <Response>
          <Say voice="woman" language="fr-FR">Merci, votre confirmation a été enregistrée. Bonne route!</Say>
        </Response>
      `,
      ar: `
        <Response>
          <Say voice="woman" language="ar-SA">شكراً، تم تسجيل تأكيدك. بالتوفيق في طريقك!</Say>
        </Response>
      `
    };
    
    res.type('text/xml');
    res.send(thankYouMessages[lang]);
  } else {
    const problemMessages = {
      fr: `
        <Response>
          <Say voice="woman" language="fr-FR">Nous avons noté votre problème. Le back-office va vous contacter.</Say>
        </Response>
      `,
      ar: `
        <Response>
          <Say voice="woman" language="ar-SA">لقد سجلنا مشكلتك. سيتصل بك المكتب قريباً.</Say>
        </Response>
      `
    };
    
    res.type('text/xml');
    res.send(problemMessages[lang]);
  }
});

// ========== TRACKING CLIENT (public) ==========

app.get('/api/track/:token', async (req, res) => {
  try {
    const transfer = await db.getTransferByToken(req.params.token);
    if (!transfer) {
      return res.status(404).json({ success: false, error: 'Transfert non trouvé' });
    }
    
    // Ne pas exposer toutes les données
    const safeData = {
      id: transfer.id,
      clientName: transfer.clientName,
      pickupDateTime: transfer.pickupDateTime,
      pickupLocation: transfer.pickupLocation,
      destination: transfer.destination,
      status: transfer.status,
      driverName: transfer.driverName
    };
    
    res.json({ success: true, transfer: safeData });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== EMERGENCY ROUTES (before static files) ==========
require('./emergency-routes')(app, db, bcrypt);

// ========== STATIC FILES ==========

app.use(express.static(path.join(__dirname, 'public')));

// Healthcheck for Railway
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Route de debug - lister les fichiers statiques
app.get('/api/debug/files', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const publicDir = path.join(__dirname, 'public');
  
  try {
    const files = fs.readdirSync(publicDir);
    res.json({ 
      success: true, 
      directory: publicDir,
      files: files
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Serveur démarré sur http://0.0.0.0:${PORT}`);
  console.log(`📊 Dashboard: http://0.0.0.0:${PORT}/dashboard.html`);
  console.log(`🔐 Login: http://0.0.0.0:${PORT}/login.html`);
});
