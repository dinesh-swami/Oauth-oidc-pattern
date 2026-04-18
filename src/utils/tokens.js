const jwt = require("jsonwebtoken");
const Token = require("../models/Token");
const { accessTokenTTL, jwtAccessSecret, jwtRefreshSecret, refreshTokenTTLDays } = require("../config/oauth");
const { randomToken, sha256 } = require("./crypto");

function addDays(date, days) {
  const next = new Date(date);
  next.setDate(next.getDate() + days);
  return next;
}

async function issueTokens({ userId, clientId, scope }) {
  const accessToken = jwt.sign(
    {
      sub: userId.toString(),
      client_id: clientId,
      scope: scope.join(" ")
    },
    jwtAccessSecret,
    { expiresIn: accessTokenTTL }
  );

  const refreshToken = randomToken(48);
  const refreshExpiresAt = addDays(new Date(), refreshTokenTTLDays);
  const accessExpiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await Token.create([
    {
      tokenHash: sha256(accessToken),
      tokenType: "access",
      clientId,
      userId,
      scope,
      expiresAt: accessExpiresAt
    },
    {
      tokenHash: sha256(refreshToken),
      tokenType: "refresh",
      clientId,
      userId,
      scope,
      expiresAt: refreshExpiresAt
    }
  ]);

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "Bearer",
    expires_in: 15 * 60,
    scope: scope.join(" ")
  };
}

function verifyAccessToken(token) {
  return jwt.verify(token, jwtAccessSecret);
}

function verifySessionToken(token) {
  return jwt.verify(token, jwtRefreshSecret);
}

function createSessionToken(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      email: user.email
    },
    jwtRefreshSecret,
    { expiresIn: "1d" }
  );
}

module.exports = {
  issueTokens,
  verifyAccessToken,
  verifySessionToken,
  createSessionToken
};
