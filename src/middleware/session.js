const User = require("../models/User");
const { sessionCookieName } = require("../config/oauth");
const { verifySessionToken } = require("../utils/tokens");

async function requireLogin(req, res, next) {
  try {
    const token = req.cookies[sessionCookieName] || req.headers["x-session-token"];
    if (!token) {
      return res.status(401).json({
        error: "login_required",
        message: "Please login first using /auth/login"
      });
    }

    const payload = verifySessionToken(token);
    const user = await User.findById(payload.sub).select("-passwordHash");
    if (!user) {
      return res.status(401).json({ error: "invalid_session" });
    }

    req.user = user;
    return next();
  } catch (error) {
    return res.status(401).json({ error: "invalid_session", message: "Session expired or invalid" });
  }
}

module.exports = {
  requireLogin
};
