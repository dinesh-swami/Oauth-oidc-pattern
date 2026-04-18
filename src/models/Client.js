const mongoose = require("mongoose");

const clientSchema = new mongoose.Schema(
  {
    clientId: {
      type: String,
      required: true,
      unique: true
    },
    clientSecretHash: {
      type: String,
      required: true
    },
    name: {
      type: String,
      required: true
    },
    redirectUris: {
      type: [String],
      required: true,
      validate: [(value) => value.length > 0, "At least one redirect URI is required"]
    },
    scopes: {
      type: [String],
      default: ["profile"]
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Client", clientSchema);
