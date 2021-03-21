//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));


//Set up app to use session pkg(after other app.use and before mongoose connect<!!!>)
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));


//Initialize passport (after session init)
app.use(passport.initialize());
//also use passport to deal with sessions
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
//ensureIndex deprecration warning
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});


userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


//Google auth-20 after session init
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", //redirect URI from google app
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //retrienve info from /userinfo instead of google+
  },
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/auth/google", 
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login"}), 
  function(req, res) {
    //Successfull authentication, redirect secrets.
    res.redirect('/secrets');
  });

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

app.get("/secrets", (req, res) => {
  //find all users with a secret
  User.find({ "secret": {$ne:null} }, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets", {usersWithSecrets: foundUsers})
    }
  })
});


app.get("/submit", (req, res) => {
  //make sure user is logged-in
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});


app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  //find who current user is
  console.log(req.user);
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      foundUser.secret = submittedSecret;
      foundUser.save(function() {
        res.redirect("/secrets");
      })
    }
  })

});


app.get("/logout", (req, res) => {
  //end user session
  req.logout();
  res.redirect("/");
});

app.post("/register", (req, res) => {

  User.register({
    username: req.body.username
  }, req.body.password, (err, newUser) => {
    if (err) {
      console.log(err);
      res.redirect('/register');
    } else {
      //callback triggered if authentication and cookie-setup successfull
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  })
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  //passport method
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      })
    }
  });

});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});