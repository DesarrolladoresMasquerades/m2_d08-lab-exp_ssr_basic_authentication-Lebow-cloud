const express = require("express");
const User = require("../models/User.model");
const saltRounds = 5;
const bcrypt = require("bcrypt");
const router = require("express").Router();



module.exports = router;
router
  .route("/signup")

  .get((req, res, next) => {
    res.render("signup");
  })

  .post((req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    // Check the form is NOT EMPTY
    if (!username || !password) {
      res.render("signup", { errorMessage: "All fields are required" });
      return;
    } else {
      User.findOne({ username }).then((user) => {
        if (user && user.username) {
          res.render("signup", { errorMessage: "User already exists" });
          throw new Error("validation error");
        }

        const salt = bcrypt.genSaltSync(saltRounds);
        const hashedPwd = bcrypt.hashSync(password, salt);

        User.create({ username, password: hashedPwd })
          .then((user) => res.render("profile", user))

          .catch((err) =>
            res.render("signup", { errorMessage: `Error from DB: ${err} ` })
          );
      });
    }
  });

  router
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })

  .post((req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password) {
      res.render("signup", { errorMessage: "All fields must be provided" });
      throw new Error("Validation Error");
    }

    User.findOne({ username })
      .then((user) => {
        if (!user) {
          res.render("login", { errorMessage: "Incorrect Credentials" });
          throw new Error("Validation Error");
        }
        const isPwdCorrect = bcrypt.compareSync(password, user.password);
        if (isPwdCorrect) {
          req.session.currentUserId = user._id; // SEND THE COOKIE BACK TO THE BROWSER
          res.redirect("/auth/profile");
          // res.render("login", { errorMessage: "Login Success"})
        } else {
          res.render("login", { errorMessage: "Incorrect Credentials" });
        }
      })
      .catch((err) => {
        console.log(err);
      });
  });
