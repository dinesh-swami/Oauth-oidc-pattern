const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");

const authRoutes = require("./routes/auth.routes");
const oauthRoutes = require("./routes/oauth.routes");
const apiRoutes = require("./routes/api.routes");

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.json({
    service: "OAuth2 Express Mongoose Demo",
    health: "/health",
    auth: ["/auth/register", "/auth/login", "/auth/me", "/auth/logout"],
    oauth: ["/oauth/authorize", "/oauth/token", "/oauth/introspect", "/oauth/revoke"],
    protectedApi: "/api/profile"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use("/auth", authRoutes);
app.use("/oauth", oauthRoutes);
app.use("/api", apiRoutes);

app.use((req, res) => {
  res.status(404).json({ error: "not_found", message: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({
    error: err.code || "server_error",
    message: err.message || "Something went wrong"
  });
});

module.exports = app;
