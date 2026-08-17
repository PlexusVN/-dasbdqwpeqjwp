const fs = require('fs');

const index = fs.readFileSync('index.js', 'utf8');
const ui = fs.readFileSync('ui_payload.html', 'utf8');

const startMarker = "app.get(['/', '/web'], (req, res) => {\n  res.send(`";
const endMarker = "`);\n});\n\n// ======================== START";

const startIndex = index.indexOf(startMarker);
const endIndex = index.indexOf(endMarker);

if (startIndex === -1 || endIndex === -1) {
  console.error("Markers not found in index.js!");
  process.exit(1);
}

// Ensure the UI string is safely escaped inside a backtick template literal
const escapedUi = ui.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');

const newIndex = index.slice(0, startIndex + startMarker.length) + escapedUi + index.slice(endIndex);

fs.writeFileSync('index.js', newIndex);
console.log("UI successfully injected!");
