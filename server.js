require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Firebase Admin SDK
const serviceAccount = {
  "type": "service_account",
  "project_id": process.env.FIREBASE_PROJECT_ID,
  "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
  "private_key": process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  "client_email": process.env.FIREBASE_CLIENT_EMAIL,
  "client_id": process.env.FIREBASE_CLIENT_ID,
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/`
});

const db = admin.firestore();

app.use(cors());
app.use(express.json());

// Middleware to verify Firebase Auth token or admin email for bulk upload
const verifyFirebaseTokenOrAdminEmail = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });
    // If Bearer token is an email, treat as admin email for bulk upload
    const token = authHeader.split('Bearer ')[1]?.trim().toLowerCase();
    const adminUsers = process.env.ADMIN_USERS ? Object.keys(JSON.parse(process.env.ADMIN_USERS)).map(e => e.trim().toLowerCase()) : [];
    console.log('Admin bulk upload token:', token, 'Allowed admins:', adminUsers);
    if (token && adminUsers.includes(token)) {
      req.user = { email: token };
      return next();
    }
    // Otherwise, treat as Firebase token
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin verification middleware
const verifyAdmin = async (req, res, next) => {
  try {
    const adminEmails = process.env.ADMIN_EMAILS?.split(',') || [];
    if (!adminEmails.includes(req.user.email)) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Admin verification failed' });
  }
};

// Auth routes
app.post('/api/auth/verify', verifyFirebaseToken, async (req, res) => {
  try {
    const user = await admin.auth().getUser(req.user.uid);
    res.json({
      uid: user.uid,
      email: user.email,
      name: user.displayName,
      verified: user.emailVerified
    });
  } catch (error) {
    res.status(400).json({ error: 'User verification failed' });
  }
});

// Public route - Get all clinics
app.get('/api/clinics', async (req, res) => {
  try {
    const clinicsSnapshot = await db.collection('clinics').get();
    const clinics = [];
    clinicsSnapshot.forEach(doc => {
      clinics.push({ id: doc.id, ...doc.data() });
    });
    res.json(clinics);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch clinics' });
  }
});

// Protected route - Get single clinic details
app.get('/api/clinics/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const clinicDoc = await db.collection('clinics').doc(req.params.id).get();
    if (!clinicDoc.exists) {
      return res.status(404).json({ error: 'Clinic not found' });
    }
    res.json({ id: clinicDoc.id, ...clinicDoc.data() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch clinic' });
  }
});

// Admin route - Add clinic
app.post('/api/clinics', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const clinic = {
      ...req.body,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user.email
    };
    const docRef = await db.collection('clinics').add(clinic);
    res.json({ id: docRef.id, ...clinic });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add clinic' });
  }
});

// Admin route - Update clinic
app.put('/api/clinics/:id', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const updateData = {
      ...req.body,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: req.user.email
    };
    await db.collection('clinics').doc(req.params.id).update(updateData);
    res.json({ id: req.params.id, ...updateData });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update clinic' });
  }
});

// Admin route - Bulk upload
app.post('/api/clinics/bulk', verifyFirebaseTokenOrAdminEmail, verifyAdmin, async (req, res) => {
  try {
    const batch = db.batch();
    const clinics = req.body.map(clinic => ({
      ...clinic,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user.email
    }));
    
    clinics.forEach(clinic => {
      const docRef = db.collection('clinics').doc();
      batch.set(docRef, clinic);
    });
    
    await batch.commit();
    res.json({ added: clinics.length });
  } catch (error) {
    res.status(500).json({ error: 'Bulk upload failed' });
  }
});

// User routes
app.post('/api/user/history', verifyFirebaseToken, async (req, res) => {
  try {
    const { clinicId } = req.body;
    const userDoc = db.collection('users').doc(req.user.uid);
    
    await userDoc.set({
      email: req.user.email,
      lastActive: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    
    await userDoc.collection('history').add({
      clinicId,
      viewedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save history' });
  }
});

app.get('/api/user/history', verifyFirebaseToken, async (req, res) => {
  try {
    const historySnapshot = await db.collection('users')
      .doc(req.user.uid)
      .collection('history')
      .orderBy('viewedAt', 'desc')
      .limit(10)
      .get();
    
    const history = [];
    historySnapshot.forEach(doc => {
      history.push({ id: doc.id, ...doc.data() });
    });
    
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Admin analytics
app.get('/api/admin/analytics', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    const clinicsSnapshot = await db.collection('clinics').get();
    
    res.json({
      totalUsers: usersSnapshot.size,
      totalClinics: clinicsSnapshot.size,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Admin login endpoint (no Firebase, just backend env)
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const adminUsers = process.env.ADMIN_USERS ? JSON.parse(process.env.ADMIN_USERS) : {};
    if (adminUsers[email] && adminUsers[email] === password) {
      // For demo: return a simple session token (in production, use JWT or session)
      return res.json({ success: true, email });
    } else {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`)); 