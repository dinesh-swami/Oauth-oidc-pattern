const router = require("express").Router();
const authController = require("../controllers/auth.controller");
const { requireLogin } = require("../middleware/session");

router.post("/register", authController.register);
router.post("/login", authController.login);
router.get("/me", requireLogin, authController.me);
router.post("/logout", authController.logout);

module.exports = router;
