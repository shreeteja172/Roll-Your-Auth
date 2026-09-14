import { Router } from "express";
import { requireAuth } from "../../auth/requireAuth";

const router: Router = Router();

router.get("/me", requireAuth, (req, res) => {
  return res.status(200).json({
    user: req.user,
  });
});
export default router;
