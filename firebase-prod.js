const admin = require("firebase-admin");

/**
 * For Render:
 * Store FULL Firebase JSON inside:
 * FIREBASE_SERVICE_ACCOUNT (Environment Variable)
 */

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT is missing");
}

const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

module.exports = admin;
