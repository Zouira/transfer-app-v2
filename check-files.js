const fs = require('fs');
const path = require('path');

console.log('=== Vérification des fichiers ===');
console.log('Dossier courant:', __dirname);
console.log('Dossier public:', path.join(__dirname, 'public'));

const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
    const files = fs.readdirSync(publicDir);
    console.log('\nFichiers dans public/:');
    files.forEach(f => console.log('  -', f));
} else {
    console.log('\n❌ Dossier public/ introuvable!');
}
