
const express = require('express')
const app = express()
const path = require("path")

const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const userModel = require("./models/user")

const cookieParser = require('cookie-parser')
const { log } = require('console')
const { readdir } = require('fs')

app.set("view engine" , "ejs")
app.use(express.json())
app.use(express.urlencoded({ extended: true}))
app.use(express.static(path.join(__dirname,'public')))
app.use(cookieParser())


app.get("/",(req,res) => {
    res.render("index")
})

app.post("/create",  (req,res) => {
    let {username, email, password, age} = req.body;

    bcrypt.genSalt(10,(err,salt) =>{
        bcrypt.hash(password, salt , async (err,hash) =>{

            let createdUser =  await userModel.create({
                username,
                email,
                password : hash,
                age
            })

            let token = jwt.sign({email}, "pass")
            res.cookie("key",token)

            res.send(createdUser)

        })
        
    } )

    
})


app.get("/login" , function(req,res){
   
    res.render('login')
})

app.post("/login", async function(req, res) {
    try {
        let user = await userModel.findOne({ email: req.body.email });
        if (!user) return res.send("User not found");

        bcrypt.compare(req.body.password, user.password, function(err, result) {
            if (err) {
                console.error("Error during password comparison:", err);
                return res.send("Error during password comparison");
            }
            if (result) {
                let token = jwt.sign({ email: user.email }, "pass");
                res.cookie("key", token);
                res.send("Yes, you can log in");
            } else {
                res.send("Invalid password");
            }
        });
    } catch (error) {
        console.error("Error during login process:", error);
        res.send("An error occurred during login");
    }
});



app.get("/logout" , function(req,res){
    res.cookie("key","")
    res.redirect('/')
})


app.listen(3000)