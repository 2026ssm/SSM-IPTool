// dhnetsdk.dll pulls in its own decode/render/stream helper DLLs from the
// SDK's Bin folder at runtime — copy everything rather than guessing which
// subset is actually needed, same approach as SSM-VMS's own copy of this
// script.
const fs = require('fs');
const path = require('path');

const sdkDir = process.env.DAHUA_SDK_DIR;
if (!sdkDir) {
  console.error('DAHUA_SDK_DIR is not set — skipping Dahua runtime DLL copy.');
  process.exit(1);
}

const binDir = path.join(sdkDir, 'Bin');
const outDir = path.join(__dirname, '..', 'build', 'Release');

if (!fs.existsSync(outDir)) {
  console.error(`Build output dir not found: ${outDir} — run node-gyp rebuild first.`);
  process.exit(1);
}

const entries = fs.readdirSync(binDir, { withFileTypes: true });
for (const entry of entries) {
  if (entry.isFile() && entry.name.toLowerCase().endsWith('.dll')) {
    fs.copyFileSync(path.join(binDir, entry.name), path.join(outDir, entry.name));
    console.log(`copied ${entry.name}`);
  }
}

console.log('Dahua runtime dependencies copied to', outDir);
