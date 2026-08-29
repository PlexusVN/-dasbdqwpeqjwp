const fs = require('fs');

const index = fs.readFileSync('index.js', 'utf8');
const ui = fs.readFileSync('ui_payload.html', 'utf8');

const sIdx = index.indexOf("app.get(['/', '/web'], (req, res) => {");
const eIdx = index.indexOf("</html>\\n`);\\n});\\n\\n// ============================================================".replace(/\\n/g, '\n'));

if (sIdx === -1 || eIdx === -1) {
  console.log("Failed to find boundaries in index.js");
  process.exit(1);
}

// Ensure the UI string is safely escaped inside a backtick template literal
const escapedUi = ui.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');

let head = index.substring(0, sIdx);
let headPrefix = "app.get(['/', '/web'], (req, res) => {\n  res.send(`";
let tail = index.substring(eIdx);

fs.writeFileSync('index.js', head + headPrefix + escapedUi + "\n" + tail);
console.log("UI successfully injected!");

