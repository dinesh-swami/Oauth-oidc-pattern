const mongoose = require("mongoose");

const authorizationCodeSchema = new mongoose.Schema(
  {
    code: {
      type: String,
      required: true,
      unique: true
    },
    clientId: {
      type: String,
      required: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    redirectUri: {
      type: String,
      required: true
    },
    scope: {
      type: [String],
      default: []
    },
    expiresAt: {
      type: Date,
      required: true
    },
    consumedAt: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

authorizationCodeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("AuthorizationCode", authorizationCodeSchema);
