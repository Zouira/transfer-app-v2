require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const Database = require('./database');
const TwilioService = require('./twilio');
const Scheduler = require('./scheduler');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'transfer-secret-key';

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

// Créer utilisateur (admin only)
app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await db.createUser(req.body);
    await db.logAudit(req.user.id, 'CREATE_USER', 'user', user.id, { username: req.body.username });
    res.json({ success: true, user });
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

// Créer chauffeur
app.post('/api/drivers', authenticateToken, async (req, res) => {
  try {
    const driver = await db.createDriver(req.body);
    await db.logAudit(req.user.id, 'CREATE_DRIVER', 'driver', driver.id, { name: driver.name });
    res.json({ success: true, driver });
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
    const { clientName, clientPhone, pickupDateTime, pickupLocation, destination, driverId, language } = req.body;
    
    // Récupérer info chauffeur
    const driver = await db.getDriverById(driverId);
    if (!driver) {
      return res.status(400).json({ success: false, error: 'Chauffeur non trouvé' });
    }

    // Créer ou récupérer client
    let client = null;
    if (clientPhone) {
      client = await db.getOrCreateClient({ name: clientName, phone: clientPhone });
    }

    const transfer = await db.createTransfer({
      clientId: client?.id,
      clientName,
      clientPhone,
      pickupDateTime,
      pickupLocation,
      destination,
      driverId: driver.id,
      driverName: driver.name,
      driverPhone: driver.phone,
      language: language || driver.language || 'fr'
    }, req.user.id);

    // Envoyer notification WhatsApp au chauffeur
    const messages = {
      fr: `🚗 Nouveau transfert assigné:\n` +
          `👤 Client: ${clientName}\n` +
          `🕐 Date/Heure: ${pickupDateTime}\n` +
          `📍 Départ: ${pickupLocation}\n` +
          `🏁 Destination: ${destination}\n\n` +
          `Répondez OK pour confirmer la réception.`,
      ar: `🚗 نقل جديد تم تعيينه:\n` +
          `👤 العميل: ${clientName}\n` +
          `🕐 التاريخ/الوقت: ${pickupDateTime}\n` +
          `📍 الانطلاق: ${pickupLocation}\n` +
          `🏁 الوجهة: ${destination}\n\n` +
          `الرد بـ OK لتأكيد الاستلام.`
    };

    await twilio.sendWhatsApp(driver.phone, messages[language || driver.language || 'fr']);

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

// Export CSV
app.get('/api/transfers/export/csv', authenticateToken, async (req, res) => {
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

app.get('/api/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const logs = await db.getAuditLogs(100);
    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== WEBHOOKS TWILIO (pas besoin d'auth) ==========

// Webhook WhatsApp
app.post('/webhook/whatsapp', async (req, res) => {
  try {
    const { From, Body } = req.body;
    const phone = From.replace('whatsapp:', '');
    
    if (Body.toLowerCase().includes('ok')) {
      const transfer = await db.getTransferByDriverPhone(phone);
      if (transfer && transfer.status === 'pending') {
        await db.updateTransferStatus(transfer.id, 'confirmed');
        
        const confirmMessages = {
          fr: '✅ Transfert confirmé. Merci!',
          ar: '✅ تم تأكيد النقل. شكراً!'
        };
        
        await twilio.sendWhatsApp(phone, confirmMessages[transfer.language || 'fr']);
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
          Bonjour, c'est le système de transfert. Vous avez une course assignée dans 2 heures.
          Appuyez sur 1 pour confirmer que vous partez, ou sur 2 si vous avez un problème.
        </Say>
        <Gather numDigits="1" action="/webhook/voice/response" method="POST">
          <Say voice="woman" language="fr-FR">Appuyez sur 1 pour confirmer.</Say>
        </Gather>
      </Response>
    `,
    ar: `
      <Response>
        <Say voice="woman" language="ar-SA">
          مرحباً، هذا نظام النقل. لديك رحلة مجدولة خلال ساعتين.
          اضغط 1 للتأكيد أنك ستنطلق، أو 2 إذا كان لديك مشكلة.
        </Say>
        <Gather numDigits="1" action="/webhook/voice/response" method="POST">
          <Say voice="woman" language="ar-SA">اضغط 1 للتأكيد.</Say>
        </Gather>
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

// ========== STATIC FILES ==========

app.use(express.static(path.join(__dirname, 'public')));

// Healthcheck for Railway
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Serveur démarré sur http://0.0.0.0:${PORT}`);
  console.log(`📊 Dashboard: http://0.0.0.0:${PORT}/dashboard.html`);
  console.log(`🔐 Login: http://0.0.0.0:${PORT}/login.html`);
});
