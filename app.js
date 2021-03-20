//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//encrypt only password field (will encrypt during save()-decrypt during find())



const User = new mongoose.model("user", userSchema);


app.get("/", function (req, res) {
  res.render("home");
});


app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/logout", function (req, res) {
  res.redirect('/');
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.post("/register", (req, res) => {
  bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });
    newUser.save((err) => {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });

    });
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({
    email: username
  }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, (err, result) => {
          if (result === true) {
            res.render("secrets");
          }
        })
      }
    }
  })
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});