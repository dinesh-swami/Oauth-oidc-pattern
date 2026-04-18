const router = require("express").Router();
const { requireBearerToken } = require("../middleware/bearer");

router.get("/profile", requireBearerToken, (req, res) => {
  res.json({
    message: "Protected profile data",
    user: req.oauth.user,
    clientId: req.oauth.clientId,
    scope: req.oauth.scope
  });
});

module.exports = router;
