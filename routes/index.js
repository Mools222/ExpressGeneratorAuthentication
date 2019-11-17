var express = require('express');
var router = express.Router();

// [Import fs]
let fs = require('fs');

// [Import bcrypt]
let bcrypt = require('bcrypt');
const saltRounds = 4;

// Get homepage
router.get('/', function (req, res, next) {
    // console.log('Cookies: ' + req.cookies);
    // console.log('Cookies connect.sid: ' + req.cookies["connect.sid"]);
    // console.log('Sessions id: ' + req.session.id);
    // console.log('Sessions cookie expires: ' + req.session.cookie._expires);

    if (req.session.user) {
        res.render('index', {
            page: 'Start',
            user: req.session.user.userName,
            password: req.session.user.password,
            expirationDate: req.session.cookie._expires
        });
    } else {
        res.render('index', {page: 'Start'});
    }
});

// Handle logins
router.post('/', function (req, res, next) {
    console.log(req.body);

    let login = checkLogin(req.body.login, req.body.password); // "login" is undefined if no such login is found - Otherwise the login object (which contains the user name and password) is returned

    if (login) { // If the login is undefined, it is converted to false. If it contains something, it is converted to true (https://www.w3schools.com/js/js_type_conversion.asp)
        console.log(`User logged in. User name: "${req.body.login}". Password: "${req.body.password}".`);

        // Save user to session
        req.session.user = {userName: req.body.login, password: req.body.password};

        // Redirect
        res.status(200).redirect('/');
    } else {
        console.log(`Someone failed to log in. User name: "${req.body.login}". Password: "${req.body.password}".`);

        res.render('index', {error: "Error: Wrong user name and/or password."})
    }
});

// Handle logouts
router.get('/logout', function (req, res, next) {
    req.session.destroy(function () {
        console.log("User logged out.")
    });
    res.status(200).redirect('/');
});

// Get create user page
router.get('/create', function (req, res, next) {
    res.render('createuser', {page: 'Create New User'});
});

// Handle create user request
router.post('/create', function (req, res, next) {
    console.log(req.body);

    let userCreated = createNewUser(req.body.login, req.body.password);

    if (userCreated === "User created.") {
        // res.status(200).redirect('/');
        res.render('createuser', {page: 'Create New User', success: "Success: " + userCreated});
    } else {
        res.render('createuser', {page: 'Create New User', error: userCreated});
    }
});

function checkLogin(userName, password) {
    let data = fs.readFileSync("../logins.json");

    let loginsArray = JSON.parse(data);

    for (let i = 0; i < loginsArray.length; i++) {
        if (loginsArray[i].login === userName && bcrypt.compareSync(password, loginsArray[i].password))
            return loginsArray[i];
    }
}

function createNewUser(userName, password) {
    if (userName.length < 1)
        return "User name must be over 1 character long.";

    let data = fs.readFileSync("../logins.json");
    let loginsArray = JSON.parse(data);

    for (let i = 0; i < loginsArray.length; i++) {
        if (loginsArray[i].login === userName)
            return "Duplicate user names cannot exist.";
    }

    // Hash password
    password = bcrypt.hashSync(password, saltRounds);

    loginsArray.push({login: userName, password: password});
    fs.writeFileSync("../logins.json", JSON.stringify(loginsArray));
    return "User created.";
}

module.exports = router;
