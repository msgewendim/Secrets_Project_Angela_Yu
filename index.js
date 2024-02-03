import express from "express";
// parsing data
import bodyParser from "body-parser";
import pg from "pg";
// this library for hashing passwords
import bcrypt from "bcrypt";
// passport for authentication login/sign-in locally & with different sites like google, facebook, git-hub etc...
import passport from "passport";
// local strategy  
import { Strategy } from "passport-local";
// authenticate with google account
import GoogleStrategy from "passport-google-oauth2";
// for keep login time , keeps cookie for storing data on the browser
import session from "express-session";
import env from "dotenv";

// create express server
const app = express();
const port = 3000;
// times the hash function will execute
const saltRounds = 10;
// configure the env file 
env.config();

// config the session of each logging to the app
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

// connect to database all params at .env file 
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// route for the homePage 
app.get("/", (req, res) => {
  res.render("home.ejs");
});

// login route sends to loginPage
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// register route => registerPage
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// ends session => homePage
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// after user logged in => secretsPage
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    //TODO: Update this to pull in the user secret to render in secrets.ejs
    try{
      // query for getting the value of secret from DB 
      const result = await db.query("SELECT secret FROM users WHERE email = $1", [req.user.email])
      // holding the secret value
      const userSecret = result.rows[0].secret;
      if (userSecret){
      // write to the secrets.ejs file the user secret and show it on the app
        res.render("secrets.ejs", {secret : userSecret})
      }else{
      // show the default secret 
        res.render("secrets.ejs", {secret : "I DON'T LIKE CHICKEN"})
      }
    }catch (error){
      console.log("fail getting secret ",error)
    }
  } else {
    // user not authenticated
    res.redirect("/login");
  }
});

// get route for the submit button 
app.get(
  "/submit", (req, res) =>{
    if (req.isAuthenticated()){
      res.render("submit.ejs")
    }else{
      res.redirect("/login")
    }
});

//  authentication with google using passport => receiving the user profile and email 
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

// after auth => secretsPage if succeed 
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// login with filled form locally => if succeed to secretsPage
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// sign-up to app local form handle = [check if user exist, hashing password, inserting to DB, render to secretsPage]
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // check if user Already sign in
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    // if so send to loginPage 
    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      // hash password submitted using "bcrypt" framework  takes the password, how much hashing to do, and callback function 
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          // inserts the new user to DB storing only the hashed password and returns the user
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          // access the user to log-in app
          const user = result.rows[0];
          req.login(user, (err) => {
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

//post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit", async (req,res) => {
  // new secret the user can submit
  const submittedSecret = req.body.secret;
  try {
    // this update the current secret with new secret => shows new secret on secretsPage
    await db.query("UPDATE users SET secret = $1 WHERE email = $2",[
      submittedSecret, 
      req.user.email]);
    res.redirect("/secrets");
  } catch (error) {
    console.log(error)
  }
})

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
