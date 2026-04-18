const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { sessionCookieName } = require("../config/oauth");
const { createSessionToken } = require("../utils/tokens");

function userResponse(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email
  };
}

async function register(req, res, next) {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "invalid_request", message: "name, email and password are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: "email_exists", message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, passwordHash });
    return res.status(201).json({ user: userResponse(user) });
  } catch (error) {
    return next(error);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "invalid_request", message: "email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "invalid_credentials", message: "Email or password is wrong" });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: "invalid_credentials", message: "Email or password is wrong" });
    }

    const sessionToken = createSessionToken(user);
    res.cookie(sessionCookieName, sessionToken, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    });

    return res.json({
      user: userResponse(user),
      sessionToken,
      note: "Browser flow uses cookie. API testing can pass this as x-session-token."
    });
  } catch (error) {
    return next(error);
  }
}

function me(req, res) {
  return res.json({ user: userResponse(req.user) });
}

function logout(req, res) {
  res.clearCookie(sessionCookieName);
  return res.json({ message: "Logged out" });
}

module.exports = {
  register,
  login,
  me,
  logout
};
