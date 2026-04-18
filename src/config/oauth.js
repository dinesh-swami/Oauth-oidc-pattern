module.exports = {
  authorizationCodeTTLMinutes: Number(process.env.AUTH_CODE_TTL_MINUTES || 10),
  accessTokenTTL: process.env.ACCESS_TOKEN_TTL || "15m",
  refreshTokenTTLDays: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7),
  sessionCookieName: process.env.SESSION_COOKIE_NAME || "oauth2_demo_session",
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET || "change_this_access_secret_for_local",
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || "change_this_refresh_secret_for_local"
};
