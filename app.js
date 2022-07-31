require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;


//Create a new express application
const app = express();

//Add a middleware for serving static files
app.use(express.static("public"));
//set the view engine to ejs
app.set('view engine', 'ejs');
//Returns middleware that only parses urlencoded bodies 
app.use(bodyParser.urlencoded({
  extended: true
}));

//Middleware to create a session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

//Initialize Passport Package
app.use(passport.initialize());
//Use passport to setup the session package
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    return cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  User.findById(id, function(err, user) {
    if (err) { return cb(err); }
    return cb(null, user);
  });
});


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
function(accessToken, refreshToken, profile, cb) {
  // console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
  callbackURL: process.env.FACEBOOK_CALLBACK_URL
},
function(accessToken, refreshToken, profile, cb) {
  // console.log(profile);
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function(req, res){
  res.render("home");
});

// (((((((((((((((GOOGLE AUTHNTICATION)))))))))))))))
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
  );

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

  // (((((((((((((((FACEBOOK AUTHNTICATION)))))))))))))))
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({"secret": {$ne: null}}, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else { 
      if (foundUsers) { 
        res.render("secrets", {usersWithSecrets: foundUsers})
      } 
    }
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});


app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  // console.log(req.user.id);
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err){
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});


app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, (err, user) => {
    if(err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });




  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  })
});







app.listen(process.env.PORT || 3000, function() {
  console.log("Server started on port 3000.");
});