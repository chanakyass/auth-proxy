// auth-proxy-service/app.js
const express = require('express');
const firebaseAdmin = require('firebase-admin');
const fetch = require('node-fetch'); // For making HTTP requests to other services
const path = require('path');
const { GoogleAuth } = require('google-auth-library'); // For internal GCP service-to-service auth

const app = express();
const port = process.env.PORT || 8080;

app.use(express.json());

// --- Firebase Admin SDK Initialization ---
// The path to your Firebase service account key JSON file
// In Cloud Run, it's best to mount this as a secret or use Application Default Credentials
// For this example, we'll assume it's directly in the directory.
// In production, use process.env to read the path or secret value.
const serviceAccountPath = path.join(__dirname, 'firebase-adminsdk.json');
const serviceAccount = require(serviceAccountPath);

firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert(serviceAccount)
});
console.log('Firebase Admin SDK initialized.');

// --- Internal Cloud Run Service URLs ---
// These will be environment variables when deployed
const HELLO_SERVICE_URL = process.env.HELLO_SERVICE_URL;

if (!HELLO_SERVICE_URL) {
  console.error('HELLO_SERVICE_URL environment variable is not set!');
  process.exit(1);
}
console.log(`Routing requests to Hello Service at: ${HELLO_SERVICE_URL}`);

// --- GoogleAuth Library for Internal Service-to-Service Authentication ---
const googleAuth = new GoogleAuth();

// Middleware to verify Firebase ID Token
app.use(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized: No token provided or invalid format');
  }

  const idToken = authHeader.split('Bearer ')[1];

  try {
    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
    req.userId = decodedToken.uid; // Attach user ID to the request object
    console.log(`Firebase ID Token verified for user: ${req.userId}`);
    next(); // Continue to the route handler
  } catch (error) {
    console.error('Error verifying Firebase ID token:', error.message);
    return res.status(403).send('Forbidden: Invalid or expired token');
  }
});

// --- Proxy Route to Hello Service ---
app.get('/hello', async (req, res) => {
  try {
    // 1. Get Google-signed ID token for internal service call
    // This token proves that this auth-proxy-service is invoking hello-service
    const client = await googleAuth.getIdTokenClient(HELLO_SERVICE_URL);
    const headers = await client.getRequestHeaders();
    headers['X-User-ID'] = req.userId; // Inject the Firebase UID for the downstream service

    // 2. Forward the request to the internal hello-service
    const response = await fetch(HELLO_SERVICE_URL, {
      method: 'GET',
      headers: headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Error from hello-service: ${response.status} - ${errorText}`);
      return res.status(response.status).send(`Error from hello-service: ${errorText}`);
    }

    const data = await response.text();
    res.status(response.status).send(data);

  } catch (error) {
    console.error('Error proxying request to hello-service:', error.message);
    res.status(500).send(`Internal Server Error: ${error.message}`);
  }
});

// Basic health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.listen(port, () => {
  console.log(`Auth Proxy Service listening on port ${port}`);
});