require("dotenv").config();

const bcrypt = require("bcryptjs");
const connectDB = require("../config/db");
const Client = require("../models/Client");

const clientId = "local-client";
const clientSecret = "local-secret";

async function seed() {
  await connectDB();

  const clientSecretHash = await bcrypt.hash(clientSecret, 12);
  await Client.findOneAndUpdate(
    { clientId },
    {
      clientId,
      clientSecretHash,
      name: "Local Demo Client",
      redirectUris: ["http://localhost:3000/callback"],
      scopes: ["profile", "email"]
    },
    { upsert: true, new: true }
  );

  console.log("Seeded OAuth client:");
  console.log(`client_id: ${clientId}`);
  console.log(`client_secret: ${clientSecret}`);
  console.log("redirect_uri: http://localhost:3000/callback");
  process.exit(0);
}

seed().catch((error) => {
  console.error(error);
  process.exit(1);
});
