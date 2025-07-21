require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Firebase Admin SDK using environment variables
const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const allowedOrigins = [
  'https://rehab-connect-pi.vercel.app',
  'http://localhost:3000'
];
app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Middleware to verify Firebase Auth token (for normal user/admin auth)
const verifyFirebaseToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Firebase token verification failed:', error);
    return res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

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

// Public route - Get single clinic details (no auth)
app.get('/api/clinics/:id', async (req, res) => {
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

// Reviews endpoints
app.get('/api/clinics/:id/reviews', async (req, res) => {
  try {
    const reviewsSnap = await db.collection('clinics').doc(req.params.id).collection('reviews').orderBy('createdAt', 'desc').get();
    const reviews = [];
    reviewsSnap.forEach(doc => {
      reviews.push({ id: doc.id, ...doc.data() });
    });
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

app.post('/api/clinics/:id/reviews', verifyFirebaseToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Review text required' });
    const userName = req.user.name || req.user.email || 'User';
    const review = {
      text,
      userId: req.user.uid,
      userName,
      createdAt: Date.now()
    };
    const reviewRef = await db.collection('clinics').doc(req.params.id).collection('reviews').add(review);
    // Increment review count
    await db.collection('clinics').doc(req.params.id).update({
      noOfReviews: admin.firestore.FieldValue.increment(1)
    });
    // Return updated reviews
    const reviewsSnap = await db.collection('clinics').doc(req.params.id).collection('reviews').orderBy('createdAt', 'desc').get();
    const reviews = [];
    reviewsSnap.forEach(doc => {
      reviews.push({ id: doc.id, ...doc.data() });
    });
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add review' });
  }
});

// Edit a review
app.put('/api/clinics/:id/reviews/:reviewId', verifyFirebaseToken, async (req, res) => {
  try {
    const { id, reviewId } = req.params;
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Review text required' });
    const reviewRef = db.collection('clinics').doc(id).collection('reviews').doc(reviewId);
    const reviewDoc = await reviewRef.get();
    if (!reviewDoc.exists) return res.status(404).json({ error: 'Review not found' });
    if (reviewDoc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Not authorized' });
    await reviewRef.update({ text });
    // Return updated reviews
    const reviewsSnap = await db.collection('clinics').doc(id).collection('reviews').orderBy('createdAt', 'desc').get();
    const reviews = [];
    reviewsSnap.forEach(doc => {
      reviews.push({ id: doc.id, ...doc.data() });
    });
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Failed to edit review' });
  }
});
// Delete a review
app.delete('/api/clinics/:id/reviews/:reviewId', verifyFirebaseToken, async (req, res) => {
  try {
    const { id, reviewId } = req.params;
    const reviewRef = db.collection('clinics').doc(id).collection('reviews').doc(reviewId);
    const reviewDoc = await reviewRef.get();
    if (!reviewDoc.exists) return res.status(404).json({ error: 'Review not found' });
    if (reviewDoc.data().userId !== req.user.uid) return res.status(403).json({ error: 'Not authorized' });
    await reviewRef.delete();
    // Decrement review count
    await db.collection('clinics').doc(id).update({
      noOfReviews: admin.firestore.FieldValue.increment(-1)
    });
    // Return updated reviews
    const reviewsSnap = await db.collection('clinics').doc(id).collection('reviews').orderBy('createdAt', 'desc').get();
    const reviews = [];
    reviewsSnap.forEach(doc => {
      reviews.push({ id: doc.id, ...doc.data() });
    });
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete review' });
  }
});

// Admin/owner reply to a review (with notification)
app.put('/api/clinics/:clinicId/reviews/:reviewId/reply', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const { clinicId, reviewId } = req.params;
    const { reply } = req.body;
    const reviewRef = db.collection('clinics').doc(clinicId).collection('reviews').doc(reviewId);
    await reviewRef.set({ reply, replyAt: Date.now(), replyBy: req.user.email }, { merge: true });
    // Fetch review to get userId
    const reviewDoc = await reviewRef.get();
    const reviewData = reviewDoc.data();
    if (reviewData && reviewData.userId) {
      // Create notification for user
      await db.collection('users').doc(reviewData.userId).collection('notifications').add({
        type: 'review_reply',
        clinicId,
        reviewId,
        reply,
        read: false,
        createdAt: Date.now(),
        message: `Your review for clinic ${clinicId} received a reply.`
      });
    }
    console.log(`Review ${reviewId} for clinic ${clinicId} replied by ${req.user.email}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reply to review' });
  }
});

// Admin hide/delete review
app.delete('/api/clinics/:clinicId/reviews/:reviewId', verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const { clinicId, reviewId } = req.params;
    await db.collection('clinics').doc(clinicId).collection('reviews').doc(reviewId).delete();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete review' });
  }
});

// User flag a review
app.post('/api/clinics/:clinicId/reviews/:reviewId/flag', verifyFirebaseToken, async (req, res) => {
  try {
    const { clinicId, reviewId } = req.params;
    await db.collection('clinics').doc(clinicId).collection('reviews').doc(reviewId).set({ flagged: true, flaggedAt: Date.now(), flaggedBy: req.user.uid }, { merge: true });
    console.log(`Review ${reviewId} for clinic ${clinicId} flagged by user ${req.user.uid}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to flag review' });
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

function extractPincode(address) {
  if (!address) return "";
  const match = address.match(/\b\d{6}\b/);
  return match ? match[0] : "";
}

const FIELD_MAP = {
  name: ["name", "Clinic Name"],
  pincode: ["pincode", "Pin Code"],
  address: ["address", "Address"],
  lat: ["lat", "latitude", "Latitude"],
  long: ["long", "longitude", "Longitude"],
  website: ["website", "site", "Site"],
  rating: ["rating", "Rating"],
  phone: ["phone", "Phone No.", "phone"],
  timings: ["timings", "Timings"],
  gmapLink: ["gMapLink", "Maps", "gmap link"],
  status: ["status", "bStatus", "Status"],
  verified: ["verified", "Verified"],
  noOfReviews: ["noOfReviews", "No of Reviews", "noOfReviews"]
};

function normalizeClinic(row) {
  const clinic = {};
  for (const [key, aliases] of Object.entries(FIELD_MAP)) {
    for (const alias of aliases) {
      if (row[alias] !== undefined && row[alias] !== null) {
        clinic[key] = row[alias];
        break;
      }
    }
    if (clinic[key] === undefined) clinic[key] = "";
  }
  // Normalize lat/long
  clinic.lat = clinic.lat ? parseFloat(clinic.lat) : "";
  clinic.long = clinic.long ? parseFloat(clinic.long) : "";
  // Normalize rating
  clinic.rating = clinic.rating ? parseFloat(clinic.rating) : "";
  // Normalize noOfReviews
  clinic.noOfReviews = clinic.noOfReviews ? parseInt(clinic.noOfReviews) : "";
  // Normalize verified
  clinic.verified = clinic.verified === true || clinic.verified === "true";
  // Normalize status
  clinic.status = clinic.status || "OPERATIONAL";
  // Normalize timings (comma separated)
  if (typeof clinic.timings === "string") {
    clinic.timings = clinic.timings.split(",").map(s => s.trim()).join(", ");
  }
  // Extract pincode if missing
  if (!clinic.pincode) {
    clinic.pincode = extractPincode(clinic.address);
  }
  return clinic;
}

// Admin route - Bulk upload
app.post('/api/clinics/bulk', verifyFirebaseTokenOrAdminEmail, verifyAdmin, async (req, res) => {
  try {
    const batch = db.batch();
    const clinics = req.body.map(normalizeClinic);
    clinics.forEach(clinic => {
      const docRef = db.collection('clinics').doc();
      batch.set(docRef, clinic);
    });
    await batch.commit();
    res.json({ added: clinics.length });
  } catch (error) {
    res.status(500).json({ error: 'Bulk upload failed', details: error.message });
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

// User profile endpoints
app.get('/api/user/profile', verifyFirebaseToken, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    const data = userDoc.exists ? userDoc.data() : {};
    res.json({
      name: data.name || req.user.name || '',
      email: data.email || req.user.email || '',
      address: data.address || '',
      phone: data.phone || '',
      gender: data.gender || ''
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.put('/api/user/profile', verifyFirebaseToken, async (req, res) => {
  try {
    const { name, email, address, phone, gender } = req.body;
    await db.collection('users').doc(req.user.uid).set({
      name: name || '',
      email: email || req.user.email || '',
      address: address || '',
      phone: phone || '',
      gender: gender || ''
    }, { merge: true });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// User favorites endpoints
app.get('/api/user/favorites', verifyFirebaseToken, async (req, res) => {
  try {
    const favSnap = await db.collection('users').doc(req.user.uid).collection('favorites').get();
    const favs = [];
    for (const docFav of favSnap.docs) {
      const favData = docFav.data();
      const clinicDoc = await db.collection('clinics').doc(favData.clinicId).get();
      if (clinicDoc.exists) {
        favs.push({ id: clinicDoc.id, ...clinicDoc.data() });
      }
    }
    res.json(favs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch favorites' });
  }
});

app.post('/api/user/favorites', verifyFirebaseToken, async (req, res) => {
  try {
    const { clinicId } = req.body;
    if (!clinicId) return res.status(400).json({ error: 'clinicId required' });
    await db.collection('users').doc(req.user.uid).collection('favorites').doc(clinicId).set({ clinicId });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

app.delete('/api/user/favorites', verifyFirebaseToken, async (req, res) => {
  try {
    const { clinicId } = req.body;
    if (!clinicId) return res.status(400).json({ error: 'clinicId required' });
    await db.collection('users').doc(req.user.uid).collection('favorites').doc(clinicId).delete();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

// User reviews endpoint
app.get('/api/user/my-reviews', verifyFirebaseToken, async (req, res) => {
  try {
    // Get all clinics
    const clinicsSnap = await db.collection('clinics').get();
    const clinics = {};
    clinicsSnap.forEach(doc => { clinics[doc.id] = doc.data(); });
    // For each clinic, get reviews by this user
    const reviews = [];
    for (const [clinicId, clinic] of Object.entries(clinics)) {
      const reviewsSnap = await db.collection('clinics').doc(clinicId).collection('reviews').where('userId', '==', req.user.uid).get();
      reviewsSnap.forEach(doc => {
        const data = doc.data();
        reviews.push({
          id: doc.id,
          clinicId,
          clinicName: clinic.name || clinicId,
          text: data.text,
          createdAt: data.createdAt,
        });
      });
    }
    // Sort by date descending
    reviews.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user reviews' });
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

// User notifications endpoints
app.get('/api/user/notifications', verifyFirebaseToken, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.user.uid).collection('notifications').orderBy('createdAt', 'desc').get();
    const notifications = [];
    snap.forEach(doc => notifications.push({ id: doc.id, ...doc.data() }));
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.post('/api/user/notifications/:notificationId/read', verifyFirebaseToken, async (req, res) => {
  try {
    const { notificationId } = req.params;
    await db.collection('users').doc(req.user.uid).collection('notifications').doc(notificationId).set({ read: true }, { merge: true });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
});

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`)); 