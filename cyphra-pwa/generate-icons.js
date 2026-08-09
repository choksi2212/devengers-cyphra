/**
 * generate-icons.js
 * Generates all required PWA icon PNGs from an SVG-like canvas drawing.
 * Run once: node generate-icons.js
 */

const { createCanvas } = require('canvas');
const fs = require('fs');
const path = require('path');

const sizes = [120, 152, 180, 192, 512];
const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) fs.mkdirSync(iconsDir);

function drawIcon(size) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');
  const r = size * 0.22; // corner radius

  // Background — dark navy
  ctx.save();
  ctx.beginPath();
  ctx.roundRect(0, 0, size, size, r);
  ctx.clip();

  // Background fill
  const bgGrad = ctx.createLinearGradient(0, 0, size, size);
  bgGrad.addColorStop(0, '#0A0F1A');
  bgGrad.addColorStop(1, '#111827');
  ctx.fillStyle = bgGrad;
  ctx.fillRect(0, 0, size, size);

  // Glow circle
  const glowGrad = ctx.createRadialGradient(size/2, size/2, 0, size/2, size/2, size*0.5);
  glowGrad.addColorStop(0, 'rgba(14,165,233,0.18)');
  glowGrad.addColorStop(1, 'rgba(14,165,233,0)');
  ctx.fillStyle = glowGrad;
  ctx.fillRect(0, 0, size, size);

  ctx.restore();

  // Shield shape
  const cx = size / 2;
  const cy = size / 2;
  const sw = size * 0.5;
  const sh = size * 0.58;
  const sx = cx - sw / 2;
  const sy = cy - sh / 2;

  const shieldGrad = ctx.createLinearGradient(sx, sy, sx + sw, sy + sh);
  shieldGrad.addColorStop(0, '#0EA5E9');
  shieldGrad.addColorStop(1, '#14B8A6');

  ctx.save();
  ctx.beginPath();
  ctx.moveTo(cx, sy);
  ctx.lineTo(sx + sw, sy + sh * 0.22);
  ctx.lineTo(sx + sw, sy + sh * 0.55);
  ctx.quadraticCurveTo(sx + sw, sy + sh, cx, sy + sh);
  ctx.quadraticCurveTo(sx, sy + sh, sx, sy + sh * 0.55);
  ctx.lineTo(sx, sy + sh * 0.22);
  ctx.closePath();
  ctx.fillStyle = shieldGrad;
  ctx.fill();
  ctx.restore();

  // Lock body (white cutout)
  const lw = sw * 0.30;
  const lh = lw * 0.80;
  const lx = cx - lw / 2;
  const ly = cy - lh * 0.1;
  const lr = lw * 0.18;

  ctx.save();
  ctx.fillStyle = 'rgba(255,255,255,0.92)';
  ctx.beginPath();
  ctx.roundRect(lx, ly, lw, lh, lr);
  ctx.fill();

  // Shackle
  ctx.strokeStyle = 'rgba(255,255,255,0.92)';
  ctx.lineWidth = size * 0.045;
  ctx.lineCap = 'round';
  ctx.beginPath();
  ctx.arc(cx, ly, lw * 0.32, Math.PI, 0);
  ctx.stroke();

  // Keyhole
  ctx.fillStyle = shieldGrad;
  ctx.beginPath();
  ctx.arc(cx, ly + lh * 0.38, lw * 0.14, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillRect(cx - lw * 0.065, ly + lh * 0.38, lw * 0.13, lh * 0.3);
  ctx.restore();

  return canvas;
}

sizes.forEach(size => {
  const canvas = drawIcon(size);
  const buf = canvas.toBuffer('image/png');
  const outPath = path.join(iconsDir, `icon-${size}.png`);
  fs.writeFileSync(outPath, buf);
  console.log(`✓ Generated icon-${size}.png`);
});

console.log('\nAll icons generated!');
