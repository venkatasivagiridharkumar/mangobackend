const express=require("express");
const {open}=require("sqlite");
const jwt=require("jsonwebtoken");
const cors=require("cors");
const bcrypt=require("bcrypt")
const path=require("path");
const sqlite3=require("sqlite3");

const app=express();
const dbPath=path.join(__dirname,"giri.db");
let db=null;
app.use(cors())
app.use(express.json())

const initializeDbAndServer=async()=>{
    try{db=await open({filename:dbPath,driver:sqlite3.Database})
    app.listen(5000,()=>{
        console.log("Server is Running at http://localhost:5000");
    })
    }
    catch(err){
        console.log(err);
        process.exit(1)
    }
}

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const userQuery = `SELECT * FROM person WHERE username = ?`;
    const userData = await db.get(userQuery, [username]);

    if (!userData) {
      return res.status(401).send("Username does not exist");
    }
    const passCheck=await bcrypt.compare(password,userData.password)
    if (passCheck) {
      const payLoad={username:username}
      const jwtToken=jwt.sign(payLoad,"MY_SECRET_TOKEN")
      res.send({"jwt_token":jwtToken})
    } else {
      res.status(401).send("Password does not match");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const checkQuery = `SELECT * FROM person WHERE username = ?`;
    const existingUser = await db.get(checkQuery, [username]);

    if (existingUser) {
      return res.status(400).send("Username already exists");
    }
    const hashedPassword=await bcrypt.hash(password,10)
    const insertQuery = `INSERT INTO person (username, password) VALUES (?, ?)`;
    await db.run(insertQuery, [username, hashedPassword]);

    res.status(200).send("Registration successful");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


app.post("/products", async (req, res) => {
  const { username, password } = req.body;

  try {
    const checkQuery = `SELECT * FROM person WHERE username = ?`;
    const existingUser = await db.get(checkQuery, [username]);

    if (existingUser) {
      return res.status(400).send("Username already exists");
    }

    const insertQuery = `INSERT INTO person (username, password) VALUES (?, ?)`;
    await db.run(insertQuery, [username, password]);

    res.status(200).send("Registration successful");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

initializeDbAndServer()