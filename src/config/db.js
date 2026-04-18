const mongoose = require("mongoose");

async function connectDB() {
  const mongoUri = process.env.MONGO_URI || "mongodb://localhost:27017/oauth2_local";
  mongoose.set("strictQuery", true);
  await mongoose.connect(mongoUri);
  console.log("MongoDB connected");
}

module.exports = connectDB;
