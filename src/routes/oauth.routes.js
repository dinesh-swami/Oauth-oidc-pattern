const router = require("express").Router();
const oauthController = require("../controllers/oauth.controller");
const { requireLogin } = require("../middleware/session");

router.get("/authorize", requireLogin, oauthController.authorize);
router.post("/token", oauthController.token);
router.post("/introspect", oauthController.introspect);
router.post("/revoke", oauthController.revoke);

module.exports = router;
