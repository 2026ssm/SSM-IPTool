// DVR_NET_SDK.dll pulls in its own decode/network/display helper DLLs from
// the same release folder at runtime — copy everything rather than
// guessing which subset is actually needed, same approach as SSM-VMS's own
// copy of this script.
const fs = require('fs');
const path = require('path');

const sdkDir = process.env.TVT_SDK_DIR;
if (!sdkDir) {
  console.error('TVT_SDK_DIR is not set — skipping TVT runtime DLL copy.');
  process.exit(1);
}

const binDir = path.join(sdkDir, 'Windows', 'bin_release', 'Release_vcx_x64');
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

console.log('TVT runtime dependencies copied to', outDir);
