// Import required modules
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect("mongodb://localhost:27017/symposiumDB");

// Define User schema and model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  userId: { type: String, unique: true },
  dept:String,
  college:String,
  phone:{ type: Number, unique: true },    
  
});

const User = mongoose.model("User", userSchema);

// Register route with auto-generated user ID
app.post("/register", async (req, res) => {
    try {
      const { name, email,password,dept,college,phone } = req.body;
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Count users for generating a unique userId
      const userCount = await User.countDocuments();
      const userId = `tech${userCount + 1}`;
  
      // Create a new user
      const newUser = new User({ name, email, password: hashedPassword, userId ,dept,college,phone});
      await newUser.save();
  
      res.status(201).json({ message: "User registered successfully!", userId });
    } catch (error) {
      // Check for duplicate key error (MongoDB error code 11000)
      if (error.code === 11000) {
        const duplicateField = Object.keys(error.keyValue)[0]; // 
        // Identify the duplicate field (email or mobile)
       
        return res.status(400).json({ message: `${duplicateField} already exists!` });
      }
      res.status(500).json({ message: "User Already exists", error });
    }
  });
  
// Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password!" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, "secretkey", { expiresIn: "1h" });

    res.status(200).json({ message: "Login successful!",token});
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
});

app.get("/profile", async (req, res) => {
    try {
      // Extract the token from the Authorization header
      const token = req.headers.authorization.split(" ")[1]; // "Bearer <token>"
      const decoded = jwt.verify(token, "secretkey"); // Verify the token with the secret key
  
      // Find the user by ID and exclude sensitive data like the password
      const user = await User.findById(decoded.userId, "-password");
      if (!user) {
        return res.status(404).json({ message: "User not found!" });
      }
 
      // Respond with user details
      res.status(200).json(user);
    } catch (error) {
      res.status(401).json({ message: "Unauthorized access", error });
    }
  });
  
 
// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
