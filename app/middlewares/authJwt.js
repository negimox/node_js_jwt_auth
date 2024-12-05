const jwt = require("jsonwebtoken");
const config = require("../config/auth.config.js");
const db = require("../models");
const User = db.user;
const Role = db.role;

verifyToken = async (req, res, next) => {
  let token = req.headers["access-token"];

  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }

  try {
    const decoded = jwt.verify(token, config.secret);
    const user = await User.findById(decoded.id);

    if (!user || user.token !== token) {
      return res.status(401).send({ message: "Session expired or invalid" });
    }

    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized!" });
  }
};

isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    const roles = await Role.find({ _id: { $in: user.roles } });

    if (roles.some((role) => role.name === "admin")) {
      return next();
    }

    res.status(403).send({ message: "Require Admin Role!" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

isModerator = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    const roles = await Role.find({ _id: { $in: user.roles } });

    if (roles.some((role) => role.name === "moderator")) {
      return next();
    }

    res.status(403).send({ message: "Require Moderator Role!" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

const authJwt = {
  verifyToken,
  isAdmin,
  isModerator,
};
module.exports = authJwt;
