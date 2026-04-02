const twilio = require('twilio');

class TwilioService {
  constructor() {
    this.client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
    this.fromNumber = process.env.TWILIO_PHONE;
    this.fromWhatsApp = process.env.TWILIO_WHATSAPP || 'whatsapp:+14155238886';

    // Numéros managers — configurable via MANAGER_WHATSAPP (virgule-séparé)
    // Exemple Railway env : MANAGER_WHATSAPP=+212612345678,+212698765432
    // Fallback : numéros de test (à remplacer en production)
    const envNumbers = process.env.MANAGER_WHATSAPP;
    if (envNumbers && envNumbers.trim()) {
      this.managerNumbers = envNumbers
        .split(',')
        .map(n => n.trim())
        .filter(n => n.length > 5)
        .map(n => n.startsWith('whatsapp:') ? n : `whatsapp:${n}`);
    } else {
      // Numéros de test — remplacer via variable d'environnement MANAGER_WHATSAPP
      this.managerNumbers = [
        'whatsapp:+212661948925',
        'whatsapp:+212616646122'
      ];
    }
    console.log(`📱 Managers WhatsApp configurés: ${this.managerNumbers.length} numéro(s)`);
  }

  // Envoyer un message WhatsApp
  async sendWhatsApp(to, message) {
    try {
      const response = await this.client.messages.create({
        from: this.fromWhatsApp,
        to: `whatsapp:${to}`,
        body: message
      });
      console.log(`✅ WhatsApp envoyé à ${to}: ${response.sid}`);
      return response;
    } catch (error) {
      console.error(`❌ Erreur WhatsApp à ${to}:`, error.message);
      throw error;
    }
  }

  // Passer un appel vocal
  async makeCall(to, transferId) {
    try {
      const baseUrl = process.env.BASE_URL;
      if (!baseUrl) {
        throw new Error('BASE_URL non configuré — appel vocal impossible');
      }
      const webhookUrl = `${baseUrl}/webhook/voice`;
      const response = await this.client.calls.create({
        from: this.fromNumber,
        to: to,
        url: webhookUrl,
        statusCallback: `${process.env.BASE_URL}/webhook/voice/status`,
        statusCallbackEvent: ['completed', 'no-answer', 'busy']
      });
      console.log(`📞 Appel passé à ${to}: ${response.sid}`);
      return response;
    } catch (error) {
      console.error(`❌ Erreur appel à ${to}:`, error.message);
      throw error;
    }
  }

  // Envoyer un message WhatsApp aux managers (alertes opérationnelles)
  async sendManagerAlert(message) {
    for (const number of this.managerNumbers) {
      try {
        await this.client.messages.create({
          from: this.fromWhatsApp,
          to: number,
          body: message
        });
        console.log(`📣 Alerte manager → ${number}`);
      } catch (err) {
        console.error(`❌ Alerte manager ${number}:`, err.message);
      }
    }
  }

  // Compatibilité ascendante (ancienne signature)
  async sendAlert(transfer, customMessage) {
    const message = customMessage ||
      `🚨 ALERTE TRANSFERT\n\n` +
      `Chauffeur ${transfer.driverName} n'a pas confirmé.\n` +
      `📅 ${transfer.pickupDateTime}\n` +
      `👤 ${transfer.clientName}\n` +
      `📍 ${transfer.pickupLocation} → ${transfer.destination}\n\n` +
      `⚠️ Intervention immédiate requise!`;
    return this.sendManagerAlert(message);
  }

  // Envoyer SMS (fallback si WhatsApp ne marche pas)
  async sendSMS(to, message) {
    try {
      const response = await this.client.messages.create({
        from: this.fromNumber,
        to: to,
        body: message
      });
      console.log(`✅ SMS envoyé à ${to}: ${response.sid}`);
      return response;
    } catch (error) {
      console.error(`❌ Erreur SMS à ${to}:`, error.message);
      throw error;
    }
  }
}

module.exports = TwilioService;
