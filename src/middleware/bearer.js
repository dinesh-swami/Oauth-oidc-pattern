const Token = require("../models/Token");
const User = require("../models/User");
const { verifyAccessToken } = require("../utils/tokens");
const { sha256 } = require("../utils/crypto");

async function requireBearerToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "invalid_token", message: "Bearer token required" });
    }

    const payload = verifyAccessToken(token);
    const tokenRecord = await Token.findOne({
      tokenHash: sha256(token),
      tokenType: "access",
      revokedAt: null
    });

    if (!tokenRecord || tokenRecord.expiresAt <= new Date()) {
      return res.status(401).json({ error: "invalid_token", message: "Token revoked or expired" });
    }

    const user = await User.findById(payload.sub).select("-passwordHash");
    if (!user) {
      return res.status(401).json({ error: "invalid_token", message: "User does not exist" });
    }

    req.oauth = {
      user,
      clientId: payload.client_id,
      scope: (payload.scope || "").split(" ").filter(Boolean)
    };

    return next();
  } catch (error) {
    return res.status(401).json({ error: "invalid_token", message: "Token invalid or expired" });
  }
}

module.exports = {
  requireBearerToken
};
