//dotenv package configuration(it is use to hide sensitive information like API key,passwords. we store all sentitive data into .env file)

require('dotenv').config();

const express = require("express");

const bodyParser = require("body-parser");

const ejs = require("ejs");

const mongoose = require("mongoose");

const session = require('express-session');

const passport=require("passport");

const passportLocalMongoose=require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate=require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));

app.use(bodyParser.urlencoded({ extended: true }));

app.set("view engine", "ejs");

//session implemenation
app.use(session({
  secret: process.env.KEY,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

//mongodb atlas connection
mongoose.connect(
  "mongodb+srv://shubham:<password>@cluster0.3x7kg.mongodb.net/SecretsDB?retryWrites=true&w=majority",
  { useUnifiedTopology: true, useNewUrlParser: true }
);
mongoose.set("useCreateIndex",true);

//collection schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  secret:   String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//User model
const User = mongoose.model("user", userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

//to save user cookies 
passport.serializeUser(function(user, done) {
  console.log("serialized  " + user.id);
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//google sign in set-up
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


app.get("/", function (req, res) {
  res.render("home");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets
    res.redirect('/secrets');
  });


app.get("/logout", function (req, res) {
  req.logout();  //passort method 
  res.redirect("/");
});



app.get("/secrets",function(req,res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){    //fetch all data where secret is not null
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

//securing password field of users collection using hashing ->md5 nodejs API
//const md5 = require("md5");

app.post("/register", function (req, res) {
 
 User.register({username:req.body.username}, req.body.password, function(err,user){
   if(err){
     console.log(err);
     res.redirect("/register");
   }
   else{
     passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
     });
   }
 })
 
  // const newUser = new User({
  //   username: req.body.username,
  //   password: md5(req.body.password), //storing password as a hash code
  // });


  // newUser.save(function (err) {
  //   if (!err) {
  //     //what to display after registration.
  //     res.render("secrets");
  //   } else {
  //     console.log(err);
  //   }
  // });
});

app.post("/login", function (req, res) {
  
  const username=req.body.username;
  const password=req.body.password;
  
  const user = new User({
    username:username,
    password:password
  });
  
  req.login(user,function(err,user){

    if(err){
      console.log(err);
      res.redirect("/login");
    }
    else{
      passport.authenticate("local")(req,res,function(){
       res.redirect("/secrets");
      });
    }
  });

  // const username = req.body.username;
  // const password = md5(req.body.password); //converting user entered password(during login) into a hash code so that we can match the existing hash code for the same password from database.

  // User.findOne({ username: username }, function (err, user) {
  //   if (!err) {
  //     if (user.password === password) {
  //       console.log(user.username, user.password);
  //       res.render("secrets");
  //     } else {
  //       console.log("Wrong username or password.");
  //       res.redirect("/");
  //     }
  //   } else {
  //     console.log(err);
  //   }
  // });
});

app.get("/submit", function (req, res) {
  if(req.isAuthenticated){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
  
});


app.post("/submit", function (req, res) {

    const submittedSecret=req.body.secret;
 
    console.log(req.user);

    User.findById(req.user.id,function(err,foundUser){
      if(err){
        console.log(err);
      }
      else{
        foundUser.secret=submittedSecret;
        foundUser.save(function(err){
          if(err){
            console.log(err);
          }
          else{
            res.redirect("/secrets");
          }
        });
      }
    });

  // newSecret.save(function (err) {
  //   if (!err) {
  //     //what to display after secret submition.
  //     res.render("secrets");
  //   } else {
  //     console.log(err);
  //   }
  // });
});

app.listen(3000, function (err) {
  if (!err) {
    console.log("Server is running on port 3000");
  } else {
    console.log(err);
  }
});








/* 

//dotenv package configuration(it is use to hide sensitive information like API key,passwords. we store all sentitive data into .env file)

require('dotenv').config();


// password protection using encryption.
//install and require mongoose-encryption to encrypt the required fields.

const encrypt=require("mongoose-encryption");

//to apply secret key on password for encryption.(here 'KEY' is the key which is stored in .env file)
userSchema.plugin(encrypt, { secret: process.env.KEY , encryptedFields: ["password"]  });

*/
