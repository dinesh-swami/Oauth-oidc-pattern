const bcrypt = require("bcryptjs");
const Client = require("../models/Client");
const AuthorizationCode = require("../models/AuthorizationCode");
const Token = require("../models/Token");
const { authorizationCodeTTLMinutes } = require("../config/oauth");
const { randomToken, sha256 } = require("../utils/crypto");
const { issueTokens } = require("../utils/tokens");

function parseScope(scope) {
  if (!scope) return ["profile"];
  return scope.split(" ").map((item) => item.trim()).filter(Boolean);
}

function invalidGrant(res, message) {
  return res.status(400).json({ error: "invalid_grant", message });
}

async function authorize(req, res, next) {
  try {
    const { response_type, client_id, redirect_uri, scope, state } = req.query;

    if (response_type !== "code") {
      return res.status(400).json({ error: "unsupported_response_type", message: "Only response_type=code is supported" });
    }

    const client = await Client.findOne({ clientId: client_id });
    if (!client) {
      return res.status(400).json({ error: "invalid_client", message: "Client not found" });
    }

    if (!client.redirectUris.includes(redirect_uri)) {
      return res.status(400).json({ error: "invalid_request", message: "redirect_uri is not registered for this client" });
    }

    const requestedScope = parseScope(scope);
    const scopeAllowed = requestedScope.every((item) => client.scopes.includes(item));
    if (!scopeAllowed) {
      return res.status(400).json({ error: "invalid_scope", message: "Requested scope is not allowed" });
    }

    const code = randomToken(32);
    const expiresAt = new Date(Date.now() + authorizationCodeTTLMinutes * 60 * 1000);

    await AuthorizationCode.create({
      code,
      clientId: client.clientId,
      userId: req.user._id,
      redirectUri: redirect_uri,
      scope: requestedScope,
      expiresAt
    });

    const url = new URL(redirect_uri);
    url.searchParams.set("code", code);
    if (state) url.searchParams.set("state", state);

    if (req.accepts("html") && !req.accepts("json")) {
      return res.redirect(url.toString());
    }

    return res.json({
      redirectTo: url.toString(),
      code,
      state: state || null
    });
  } catch (error) {
    return next(error);
  }
}

async function validateClient(clientId, clientSecret) {
  const client = await Client.findOne({ clientId });
  if (!client) return null;

  const validSecret = await bcrypt.compare(clientSecret || "", client.clientSecretHash);
  return validSecret ? client : null;
}

async function token(req, res, next) {
  try {
    const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;
    const client = await validateClient(client_id, client_secret);
    if (!client) {
      return res.status(401).json({ error: "invalid_client", message: "Client credentials are wrong" });
    }

    if (grant_type === "authorization_code") {
      const codeRecord = await AuthorizationCode.findOne({ code, clientId: client.clientId });
      if (!codeRecord) return invalidGrant(res, "Authorization code not found");
      if (codeRecord.consumedAt) return invalidGrant(res, "Authorization code already used");
      if (codeRecord.expiresAt <= new Date()) return invalidGrant(res, "Authorization code expired");
      if (codeRecord.redirectUri !== redirect_uri) return invalidGrant(res, "redirect_uri does not match");

      codeRecord.consumedAt = new Date();
      await codeRecord.save();

      const tokens = await issueTokens({
        userId: codeRecord.userId,
        clientId: client.clientId,
        scope: codeRecord.scope
      });

      return res.json(tokens);
    }

    if (grant_type === "refresh_token") {
      const refreshRecord = await Token.findOne({
        tokenHash: sha256(refresh_token || ""),
        tokenType: "refresh",
        clientId: client.clientId,
        revokedAt: null
      });

      if (!refreshRecord) return invalidGrant(res, "Refresh token not found");
      if (refreshRecord.expiresAt <= new Date()) return invalidGrant(res, "Refresh token expired");

      refreshRecord.revokedAt = new Date();
      await refreshRecord.save();

      const tokens = await issueTokens({
        userId: refreshRecord.userId,
        clientId: client.clientId,
        scope: refreshRecord.scope
      });

      return res.json(tokens);
    }

    return res.status(400).json({ error: "unsupported_grant_type", message: "Use authorization_code or refresh_token" });
  } catch (error) {
    return next(error);
  }
}

async function introspect(req, res, next) {
  try {
    const { token: rawToken, client_id, client_secret } = req.body;
    const client = await validateClient(client_id, client_secret);
    if (!client) {
      return res.status(401).json({ error: "invalid_client", message: "Client credentials are wrong" });
    }

    const record = await Token.findOne({ tokenHash: sha256(rawToken || ""), clientId: client.clientId });
    if (!record || record.revokedAt || record.expiresAt <= new Date()) {
      return res.json({ active: false });
    }

    return res.json({
      active: true,
      token_type: record.tokenType,
      client_id: record.clientId,
      user_id: record.userId,
      scope: record.scope.join(" "),
      exp: Math.floor(record.expiresAt.getTime() / 1000)
    });
  } catch (error) {
    return next(error);
  }
}

async function revoke(req, res, next) {
  try {
    const { token: rawToken, client_id, client_secret } = req.body;
    const client = await validateClient(client_id, client_secret);
    if (!client) {
      return res.status(401).json({ error: "invalid_client", message: "Client credentials are wrong" });
    }

    await Token.updateOne(
      { tokenHash: sha256(rawToken || ""), clientId: client.clientId, revokedAt: null },
      { $set: { revokedAt: new Date() } }
    );

    return res.status(200).json({ revoked: true });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  authorize,
  token,
  introspect,
  revoke
};
