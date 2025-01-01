const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

//files
const connect = require('./confing/connection');
const userModel = require('./models/user');



app.use(express.json());
app.use(express.urlencoded({extended:true}));
require('dotenv').config();
app.use(cors({
    origin:"http://localhost:5173",
    credentials: true
}));
app.use(cookieParser());

app.get('/',(req,res)=>{
    res.send("Hello");
});

app.post('/register',async (req,res)=>{
    const {name,email,password,phone} = req.body
   try{
    const salt = await bcrypt.genSalt(10);
    console.log("salt is",salt)
    const hash = await bcrypt.hash(password, salt);
    const user = await userModel.create({
        username:name,
        email:email,
        password:hash,
        phone:phone
    });
    
   const token =  jwt.sign({userid:user._id},"Secretkey");
   res.cookie("token", token, { httpOnly: true });
   res.send("user Created successfully");
   console.log("Cookie is Set", token);
   }catch(err){
    if(err){
        res.send("Something went wrong");
    }
   }
});


app.post('/login', async (req, res) => {
    const { name, password } = req.body;
    console.log("Received login attempt with name and password:", name, password);

    try {
        const user = await userModel.findOne({ username: name });
        if (!user) {
            console.log("User not found");
            return res.status(404).send("User not found");
        }

        console.log("User found:", user);

        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error("Error during authentication:", err);
                return res.status(500).send("Error during authentication");
            }

            if (result) {
                const token = jwt.sign({ user: user._id }, "Secretkey");
                res.cookie('token', token, { httpOnly: true });
                return res.status(200).send("Login successful");
            } else {
                console.log("Invalid credentials");
                return res.status(401).send("Invalid credentials");
            }
        });
    } catch (err) {
        console.error("Error occurred:", err);
        res.status(500).send("An error occurred");
    }
});




app.get('/isloggedin', (req, res) => {
    if (!req.cookies.token) {
        return res.send({ isLoggedIn: false });
    }
    try {
        const data = jwt.verify(req.cookies.token, "Secretkey");
        req.user = data;
        res.send({ isLoggedIn: true });
    } catch (err) {
        res.send({ isLoggedIn: false });
    }
});


app.listen(3000);