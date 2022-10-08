//validate karavanu che SQL injection vadu
var express = require("express"),
    session = require("express-session"),
    bodyParser = require('body-parser'),
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

app.use(session({secret:'Keep it secret'
,name:'uniqueSessionID'
,saveUninitialized:false}))
 
//Showing default page
app.get("/", function (req, res) {
    res.render("login");
});
//Showing Home page
app.get("/home", function (req, res) {
    console.log(req.session.id);
    console.log(req.session.username);
    if(req.session.id!=null)
    {res.render('home');}
    else
    {res.redirect('/login');}
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
    var hash_passwd = crypto.createHash('sha256').update(encrypt_passwd).digest('hex');
    let stmt = "INSERT INTO register VALUES (?,?)";
    let dict=[encrypt_username,hash_passwd];
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
    if(req.session.loggedIn)
    {res.redirect('home');}
    else
    {res.redirect('/login');}
});
//Handling user login
app.post("/login",  function (req, res) {
    var username = req.body.username
    var password = req.body.password
    var encrypt_username = monoalphabeticCipher.encipher(username);
    var encrypt_passwd = monoalphabeticCipher.encipher(password);
    var hash_passwd = crypto.createHash('sha256').update(encrypt_passwd).digest('hex');
    let stmt = "SELECT username FROM register WHERE username = ? AND passwd = ?";
    connection.query(stmt, [encrypt_username,hash_passwd],(err, result) => {
        if (err) {
          return console.error("Error::"+err.message);
        }
        if (result[0].username != undefined ){
            req.session.isLoggedIn=true;
            req.session.username=monoalphabeticCipher.decipher(result[0].username);
            res.redirect("home");
        }
        else{
            res.render("login");
        }
      });
});
 
//Handling user logout
app.get("/logout", function (req, res) {
    req.session.destroy();
    res.redirect("/");
});

var port = process.env.PORT || 3000;
app.listen(port, function () {
    console.log("Server Has Started! on http://localhost:3000/");
});


//connection.end();