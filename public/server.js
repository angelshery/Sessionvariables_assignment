// User Authentication Server
// Lets users register and log in. Passwords are never stored in plain text: each one is salted and hashed before saving.

const express = require("express");

// crypto: built-in Node module used for salting and hashing passwords
const crypt = require("crypto");
const app = express();

// mysql2: library that lets Node talk to the MySQL database
const mysql = require("mysql2");

// Middleware
app.use(express.urlencoded({ extended: true }));
//app.use(express.static("public"));

// MySQL connection
const pass = process.env.ROOTPASS;

const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: pass,
    database: "paws",
    port: 3306
});

// Password hashing settings
const hashRounds = 100;
const hashLength = 64;

// Connect to MySQL
conn.connect(function(err) {
    if (err)
        console.log("Couldn't connect to MySQL", err);
    else
        console.log("Database connection established");
});

// REGISTER
app.post("/register", function(req, res) {

    let username = req.body.username;
    let fname = req.body.fname;
    let lname = req.body.lname;
    let email = req.body.email;
    let plainPass = req.body.password;

    // Generate salt
    const salt = crypt.randomBytes(16).toString("hex");

    // Hash password
    const hashedPass = crypt.pbkdf2Sync(
        plainPass,
        salt,
        hashRounds,
        hashLength,
        "sha512"
    ).toString("hex");

    // Insert user into database
    let sql = "INSERT INTO users (username, fname, lname, email, password, salt) VALUES (?, ?, ?, ?, ?, ?)";

    conn.query(sql, [username, fname, lname, email, hashedPass, salt], function(err, result) {

        if (err) {
            console.log("There was an error inserting a user", err);

            if (err.code === "ER_DUP_ENTRY") {
                res.send(`
                    <p>Username or email already exists!</p>
                    <a href="register.html">Register again</a>
                `);
            }
            else {
                res.send("Registration failed");
            }
        }
        else {
            res.send(`
                <h2>You have successfully registered!</h2>
                <a href="login.html">Login here</a>
            `);
        }

    });

});

// LOGIN
app.post("/login", function(req, res) {

    let username = req.body.username;
    let plainPass = req.body.password;

    // Find user in database
    let sql = "SELECT * FROM users WHERE username = ?";

    conn.query(sql, [username], function(err, result) {

        if (err) {
            console.log("Login database error", err);
            res.send("Login failed");
        }
        else {

            if (result.length === 0) {
                res.send(`
                    <p>The login credentials were incorrect.</p>
                    <a href="login.html">Login again</a>
                `);
            }
            else {

                // Get stored salt
                const salt = result[0].salt;

                // Hash entered password
                const hashedPass = crypt.pbkdf2Sync(
                    plainPass,
                    salt,
                    hashRounds,
                    hashLength,
                    "sha512"
                ).toString("hex");

                // Compare passwords
                if (hashedPass === result[0].password) {
                    req.session.user = user;
                    req.session.save();
                    res.send(`
                        <h2>You have logged in successfully!</h2>
                        <a href="login.html">Back to Login</a>
                    `);
                }
                else {
                    res.send(`
                        <p>The login credentials were incorrect.</p>
                        <a href="login.html">Login again</a>
                    `);
                }

            }
        }

    });

});

app.get("/profile", (req, res) => {
    if(req.session.user)
    {
    const sessionuser = req.session.user;
    console.log("users only info")
    res.send(sessionuser);
    }
    else
    {
        res.send("<p>You have not logged in. Please visit<a href='/login.html'>the login page</a></p>");
    }
});

//LOGOUT
app.get("/logout", (req, res) => 
{
    req.session.destroy((err)=> 
	{
		if (err) res.send("Error logging out");
		else res.send('Logged out successfully!');
	});
    
});

// Start server and listen for requests on port 3000
app.listen(3000, function() {
    console.log("Server running at http://localhost:3000");
});

