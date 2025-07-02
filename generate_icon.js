const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

// Create a 512x512 canvas
const canvas = createCanvas(512, 512);
const ctx = canvas.getContext('2d');

// Draw circular background with gradient
ctx.save();
ctx.beginPath();
ctx.arc(256, 256, 252, 0, 2 * Math.PI);
ctx.closePath();
ctx.clip();

const gradient = ctx.createLinearGradient(0, 0, 512, 512);
gradient.addColorStop(0, '#1e293b');
gradient.addColorStop(1, '#0f172a');
ctx.fillStyle = gradient;
ctx.fillRect(0, 0, 512, 512);
ctx.restore();

// Draw circular border
ctx.save();
ctx.beginPath();
ctx.arc(256, 256, 252, 0, 2 * Math.PI);
ctx.closePath();
ctx.lineWidth = 8;
ctx.strokeStyle = '#374151';
ctx.stroke();
ctx.restore();

// Draw large, sharp-bottom green shield, vertically centered
const yOffset = -30; // Raise the shield by 30px
ctx.save();
ctx.shadowColor = 'rgba(16, 185, 129, 0.3)';
ctx.shadowBlur = 24;
ctx.beginPath();
ctx.moveTo(256, 100 + yOffset); // Top center
ctx.lineTo(400, 170 + yOffset); // Top right
ctx.lineTo(400, 290 + yOffset); // Right side
ctx.quadraticCurveTo(400, 390 + yOffset, 256, 470 + yOffset); // Right curve to sharp bottom
ctx.quadraticCurveTo(112, 390 + yOffset, 112, 290 + yOffset); // Left curve
ctx.lineTo(112, 170 + yOffset); // Top left
ctx.closePath();
ctx.fillStyle = '#10b981';
ctx.fill();
ctx.restore();

// Save the icon
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir);
}

const buffer = canvas.toBuffer('image/png');
fs.writeFileSync(path.join(assetsDir, 'icon.png'), buffer);

console.log('✅ Icon generated successfully at assets/icon.png');
console.log('🎨 Icon features:');
console.log('   - Circular dark theme gradient background');
console.log('   - Large green shield with a sharp bottom, centered');
console.log('   - Clean, minimalist design with no internal elements');
console.log('   - Subtle glow effects matching the app aesthetic'); 