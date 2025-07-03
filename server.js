const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

const DATA_FILE = path.join(__dirname, 'clinics.json');

function readClinics() {
  if (!fs.existsSync(DATA_FILE)) return [];
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
}
function writeClinics(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

app.get('/api/clinics', (req, res) => {
  res.json(readClinics());
});

app.post('/api/clinics', (req, res) => {
  const clinics = readClinics();
  const newClinic = req.body;
  clinics.push(newClinic);
  writeClinics(clinics);
  res.json(newClinic);
});

app.put('/api/clinics/:id', (req, res) => {
  const clinics = readClinics();
  const idx = clinics.findIndex(c => String(c.id) === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Clinic not found' });
  clinics[idx] = { ...clinics[idx], ...req.body };
  writeClinics(clinics);
  res.json(clinics[idx]);
});

app.post('/api/clinics/bulk', (req, res) => {
  const clinics = readClinics();
  clinics.push(...req.body);
  writeClinics(clinics);
  res.json({ added: req.body.length });
});

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`)); 