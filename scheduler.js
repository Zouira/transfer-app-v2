const cron = require('node-cron');

// Formate une date ISO en lisible FR : "02 avr. à 14h30"
function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString('fr-FR', {
      day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
  } catch(e) { return iso || '?'; }
}

// Formate uniquement l'heure : "14h30"
function fmtTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  } catch(e) { return iso || '?'; }
}

class Scheduler {
  constructor(db, twilio) {
    this.db = db;
    this.twilio = twilio;
  }

  start() {
    console.log('⏰ Scheduler démarré');

    // Vérification toutes les minutes
    cron.schedule('* * * * *', async () => {
      await this.checkTransfers();
    });

    // Backup quotidien à 3h
    cron.schedule('0 3 * * *', async () => {
      console.log('💾 Backup quotidien...');
      try {
        const backupPath = await this.db.backup();
        console.log('✅ Backup créé:', backupPath);
      } catch (err) {
        console.error('❌ Erreur backup:', err.message);
      }
    });
  }

  async checkTransfers() {
    try {
      // 1. Rappel WhatsApp au chauffeur à T-1h30
      await this.handleDriverReminders();

      // 2. Alerte manager si pas de GO à T-1h
      await this.handleManagerAlerts();

      // 3. Alerte manager si toujours en cours après GO+2h
      await this.handleGoAlerts();

    } catch (error) {
      console.error('Erreur scheduler:', error.message);
    }
  }

  // ─── ÉTAPE 1 : Rappel chauffeur T-1h30 ────────────────────────────────────
  async handleDriverReminders() {
    const transfers = await this.db.getTransfersNeedingDriverReminder();
    if (transfers.length > 0) {
      console.log(`⏰ ${transfers.length} rappel(s) chauffeur T-1h30`);
    }

    for (const t of transfers) {
      try {
        const lang = t.language || 'fr';
        const heure = fmtTime(t.pickupDateTime);

        const messages = {
          fr: `⏰ *RAPPEL TRANSFERT — dans 1h30*\n\n` +
              `Transfert #${t.id}\n` +
              `🕐 Heure prévue : *${heure}*\n` +
              `👤 Client : ${t.clientName}\n` +
              `📍 Départ : ${t.pickupLocation}\n` +
              `🏁 Destination : ${t.destination}\n\n` +
              `Confirmez votre disponibilité en répondant *GO*.`,

          ar: `⏰ *تذكير النقل — بعد 1h30*\n\n` +
              `النقل #${t.id}\n` +
              `🕐 الوقت المحدد: *${heure}*\n` +
              `👤 العميل: ${t.clientName}\n` +
              `📍 الانطلاق: ${t.pickupLocation}\n` +
              `🏁 الوجهة: ${t.destination}\n\n` +
              `أكد توفرك بالرد بـ *GO*.`
        };

        await this.twilio.sendWhatsApp(t.driverPhone, messages[lang] || messages.fr);
        await this.db.markDriverReminderSent(t.id);
        console.log(`✅ Rappel T-1h30 → chauffeur #${t.id} (${t.driverName})`);
      } catch (err) {
        console.error(`❌ Rappel T-1h30 transfert #${t.id}:`, err.message);
      }
    }
  }

  // ─── ÉTAPE 2 : Alerte manager T-1h (pas de GO) ────────────────────────────
  async handleManagerAlerts() {
    const transfers = await this.db.getTransfersNeedingManagerAlert();
    if (transfers.length > 0) {
      console.log(`🔴 ${transfers.length} alerte(s) manager T-1h`);
    }

    for (const t of transfers) {
      try {
        const message =
          `🔴 *ALERTE — Chauffeur non confirmé*\n\n` +
          `Transfert *#${t.id}* dans moins d'1 heure !\n` +
          `📅 ${fmtDate(t.pickupDateTime)}\n` +
          `👤 Client : ${t.clientName}\n` +
          `🚖 Chauffeur : ${t.driverName} (${t.driverPhone})\n` +
          `📍 ${t.pickupLocation} → ${t.destination}\n\n` +
          `⚡ Contactez le chauffeur immédiatement.`;

        await this.twilio.sendManagerAlert(message);
        await this.db.markAlertSent(t.id);
        console.log(`🔴 Alerte manager → transfert #${t.id} (${t.clientName})`);
      } catch (err) {
        console.error(`❌ Alerte manager transfert #${t.id}:`, err.message);
      }
    }
  }

  // ─── ÉTAPE 3 : Alerte manager GO+2h (toujours en cours) ───────────────────
  async handleGoAlerts() {
    const transfers = await this.db.getInProgressTransfersNeedingGoAlert();
    if (transfers.length > 0) {
      console.log(`⚠️  ${transfers.length} alerte(s) GO+2h`);
    }

    for (const t of transfers) {
      try {
        const message =
          `⚠️ *VÉRIFICATION REQUISE*\n\n` +
          `Transfert *#${t.id}* toujours "En cours" (2h+)\n` +
          `🚖 Chauffeur : ${t.driverName} (${t.driverPhone})\n` +
          `👤 Client : ${t.clientName}\n` +
          `📍 ${t.pickupLocation} → ${t.destination}\n\n` +
          `Confirmez si la mission est terminée (appuyez FIN dans l'app).`;

        await this.twilio.sendManagerAlert(message);
        await this.db.markGoAlertSent(t.id);
        console.log(`⚠️  Alerte GO+2h → transfert #${t.id} (${t.driverName})`);
      } catch (err) {
        console.error(`❌ Alerte GO+2h transfert #${t.id}:`, err.message);
      }
    }
  }
}

module.exports = Scheduler;
