//validate karavanu che SQL injection vadu
var express = require("express"),
    passport = require("passport"),
    bodyParser = require("body-parser"),
    LocalStrategy = require("passport-local"),
    passportLocalMongoose = require("passport-local-mongoose"),
    User = require("./models/user"),
    MonoAlphabeticCipher = require('text-ciphers').MonoAlphabeticCipher,
    monoalphabeticCipher = new MonoAlphabeticCipher({
        substitution: MonoAlphabeticCipher.createKeyByShift(-5)
    }),
    crypto = require('crypto');
const mysql = require('mysql');
 
var connection = mysql.createConnection({
    host:"database-1.cxjhcqoiuwd1.us-east-1.rds.amazonaws.com",
    user:"admin",
    password:"csproject",
    port:"3306",
    database:"register"
});
connection.connect(function(err){
    if(err){
        console.error('Database failed:'+err.stack);
        return;
    }
    console.log("Database Connected");
});

//mongoose.connect("mongodb://localhost/cs_project_app");
var app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(require("express-session")({
    secret: "Rusty is a dog",
    resave: false,
    saveUninitialized: false
}));
 
app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
//Showing default page
app.get("/", function (req, res) {
    res.render("login");
});
//Showing Home page
app.get("/index", isLoggedIn, function (req, res) {
    res.render("index");
});
// Showing register form
app.get("/register", function (req, res) {
    res.render("register");
});
// Handling user signup
app.post("/register", function (req, res) {
    var username = req.body.username
    var password = req.body.password
    console.log(username);
    console.log(password);
    var encrypt_username = monoalphabeticCipher.encipher(username);
    var encrypt_passwd = monoalphabeticCipher.encipher(password);
    var hash_username = crypto.createHash('sha256').update(encrypt_username).digest('hex');
    var hash_passwd = crypto.createHash('sha256').update(encrypt_passwd).digest('hex');
    let stmt = "INSERT INTO register VALUES (?,?)";
    let dict=[hash_username,hash_passwd];
    connection.query(stmt, dict, (err, results, fields) => {
        if (err) {
          return console.error(err.message);
        }
        // get inserted id
        console.log(results.insertId);
      });
      res.redirect("login");
});
//Showing login form
app.get("/login", function (req, res) {
    res.render("login");
});
//Handling user login
app.post("/login", passport.authenticate("local", {
    successRedirect: "/index",
    failureRedirect: "/login"
}), function (req, res) {
});
 
//Handling user logout
app.get("/logout", function (req, res) {
    req.logout();
    req.session.destroy();
    res.redirect("/");
});
 
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect("/login");
}
 
var port = process.env.PORT || 3000;
app.listen(port, function () {
    console.log("Server Has Started! on http://localhost:3000/");
});


//connection.end();