// Import express
const express = require('express');
// Import mongoose
const mongoose = require('mongoose');
// use express
const router = express();
// Import customer model
const Customer = require('./models/customerModel');
// Import bcrypt for salt and hashing password
const bcrypt = require('bcrypt');


// Middleware
// Enable JSON in API
router.use(express.json());


// Utility function to validate inputs using advanced RegEx patterns
const validateInput = (value, pattern) => {
    return pattern.test(value);
}

// Advanced RegEx patterns for input validation

// Full name Regular Expression pattern for whitelisting
const fullNamePattern = /^[a-zA-Z\s\-']{3,100}$/;
// ID Number Regular Expression pattern for whitelisting
const idNumberPattern = /^[a-zA-Z0-9]{10,13}$/
// Account number Regular Expression pattern for whitelisting
const accountNumberPattern = /^[0-9]{8,12}$/
// Username Regular Expression pattern for whitelisting
const usernamePattern = /[a-zA-Z0-9_]{3,30}$/
// Passwor Regular Expression for whitelisting
const passwordPattern = /^[a-zA-z0-9]!@£$%^&*]{6,50}$/


// Routes
// Register Route
router.post('/register', async (req, res) => {
    // Store values from requst body
    const { fullName, idNumber, accountNumber, username, password } = req.body;

    // Perform input whitelisting checks on all inputs

    // Input whitelisting through RegEx for full name
    if (!validateInput(fullName, fullNamePattern)){
        return res.status(400).json({ message: "Invalid full name format." });
    }
    // Input whitelisting through RegEx for ID number
    if (!validateInput(idNumber, idNumberPattern)){
        return res.status(400).json({ message: "Invalid ID number format." });
    }
    // Input whitelisting through RegEx for account number
    if (!validateInput(accountNumber, accountNumberPattern)){
        return res.status(400).json({ message: "Invalid account number format." });
    }
    // Input whitelisting through RegEx for username
    if (!validateInput(username, usernamePattern)){
        return res.status(400).json({ message: "Invalid username format." });
    }
    // Input whitelisting through RegEx for password
    if (!validateInput(password, passwordPattern)){
        return res.status(400).json({ message: "Inavlid password format." })
    }

    // Perform additional checks and only register user if pass
    try{
        // Check if username or account number already exists in DB
        const existingUser = await Customer.findOne({ $or: [{ username }, { accountNumber }] });
        // If a user already exists
        if (existingUser){
            // Display error message to user
            return res.status(400).json({ message: "Username or acccount number already exists"})
        }

        // Password Security
        // Get Salt
        const salt = await bcrypt.genSalt(10);
        // Hash Password
        const passwordHash = await bcrypt.hash(password, salt);

        // Create a new customer
        const customer = await Customer.create({
            fullName,
            idNumber,
            accountNumber,
            username,
            passwordHash
        });

        // Success message
        await customer.save();
        res.status(201).json({ message: "User registered successfully"});
    } 
    // Catch error from try
    catch (error){
        // Server error message
        res.status(500).json({message: "Server error: " + error});
    }
})

// Login Route
router.post('/login', async (req, res)=>{
    // Get username and password from request
    const { username, password } = req.body;

    // Perform input whitelisting checks on all inputs

    // Input whitelisting through RegEx for username
    if (!validateInput(username, usernamePattern)){
        return res.status(400).json({ message: "Invalid username format."})
    }
    // Input whitelisting through RegEx for password
    if (!validateInput(password, passwordPattern)){
        return res.status(400).json({ message: "Invalid password format."});
    }

    // Perform additional checks and only login user if pass
    try{
        // Find user by username
        const user = await Customer.findOne({ username });
        // If the user doesn't exist
        if(!user){
            // Show error message
            return res.status(401).json({message: "Username does not exist"});
        }

        // Salt and hash password verifcation
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        // If salt and hash password verification failed 
        if (!isMatch){
            // Show error message
            return res.status(401).json({ message: "Password is incorrect"})
        }

        // Else login is successful
        res.status(200).json({ message: "Login successful", user: {fullName: user.fullname, username: user.username } })

    } 
    // Catch an error
    catch (error){
        res.status(500).json({ message: "Server error: " + error})
    }

})



// Connect to MongoDB
mongoose
.connect('mongodb+srv://denzel:Password123@mongodbcluster.uos1u.mongodb.net/APDS-Node-API?retryWrites=true&w=majority&appName=MongoDbCluster')
.then(() => {
    // Only connect to API after connecting to MongoDB successfully
    router.listen(3000, ()=>{
        console.log("APDS Node API is running on port 3000")
    });
    console.log('Connected to MongoDB');
}).catch((error) =>{
    // Display the error if fails
    console.log(error);
})