const twilio = require('twilio');

class TwilioService {
  constructor() {
    this.client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
    this.fromNumber = process.env.TWILIO_PHONE;
    this.fromWhatsApp = process.env.TWILIO_WHATSAPP || 'whatsapp:+14155238886';
    
    // Numéros des responsables pour les alertes
    this.alertNumbers = [
      'whatsapp:+212661948925',  // Ami
      'whatsapp:+212616646122'   // Collègue
    ];
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

  // Envoyer une alerte aux responsables
  async sendAlert(transfer, customMessage) {
    const message = customMessage || 
      `🚨 ALERTE TRANSFERT\n\n` +
      `Le chauffeur ${transfer.driverName} n'a pas confirmé le transfert.\n\n` +
      `📅 Date/Heure: ${transfer.pickupDateTime}\n` +
      `👤 Client: ${transfer.clientName}\n` +
      `📍 Départ: ${transfer.pickupLocation}\n` +
      `🏁 Destination: ${transfer.destination}\n\n` +
      `⚠️ Intervention immédiate requise!`;

    for (const number of this.alertNumbers) {
      try {
        await this.client.messages.create({
          from: this.fromWhatsApp,
          to: number,
          body: message
        });
        console.log(`🚨 Alerte envoyée à ${number}`);
      } catch (error) {
        console.error(`❌ Erreur alerte à ${number}:`, error.message);
      }
    }
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
