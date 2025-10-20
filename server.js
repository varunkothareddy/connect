// --- NEW LOG AT VERY TOP ---
console.log('>>> SERVER.JS FILE IS STARTING <<<');

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// --- NEW LOG ---
console.log('>>> MODULES LOADED <<<');

const app = express();
app.use(cors());
app.use(express.json());

// --- NEW LOG ---
console.log('>>> EXPRESS APP INITIALIZED <<<');


// --- Database Connection ---
const MONGO_URI = 'mongodb://localhost:27017/weconnectyou';
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => {
        console.error('Initial MongoDB connection error:', err);
        process.exit(1); // Exit if cannot connect initially
    });

// Added listener for runtime errors after initial connection
mongoose.connection.on('error', err => {
  console.error('MongoDB runtime connection error:', err);
});

// --- Schemas ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Name is required'] },
    mobile: {
        type: String,
        required: [true, 'Mobile number is required'],
        unique: true,
        match: [/^[0-9]{10}$/, 'Mobile number must be 10 digits']
    },
    password: { type: String, required: [true, 'Password is required'] }
}, { timestamps: true }); // Added timestamps for User if needed later
const User = mongoose.model('User', UserSchema);

const WorkerSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Worker name is required'] },
    mobile: {
        type: String,
        required: [true, 'Worker mobile number is required'],
        match: [/^[0-9]{10}$/, 'Mobile number must be 10 digits']
    },
    location: { type: String, required: [true, 'Location is required'] },
    workType: { type: String, required: [true, 'Work type is required'] },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true }); // Timestamps added here
const Worker = mongoose.model('Worker', WorkerSchema);

// --- JWT Secret & Middleware ---
// IMPORTANT: Use an environment variable for JWT_SECRET in production
const JWT_SECRET = 'my-super-secret-key-for-this-12k-project-CHANGE-THIS-LATER';

const authMiddleware = (req, res, next) => {
    console.log('--- Auth Middleware Running ---'); // Debug log
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (token == null) {
        console.log('Auth Middleware: No token provided'); // Debug log
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Add user info { userId, mobile, name } to the request object
        console.log('Auth Middleware: Token verified for user:', req.user.userId); // Debug log
        next(); // Token is valid, proceed
    } catch (err) {
        console.error("Auth Middleware: JWT Verification Error:", err.message); // Log the specific error
        res.status(403).json({ message: 'Invalid or expired token.' }); // 403 Forbidden
    }
};

// --- Routes ---

// Register Route
app.post('/api/register', async (req, res) => {
    console.log('[POST /api/register] Received request');
    console.log('Request body:', req.body);
    try {
        const { name, mobile, password } = req.body;

        // Backend Validation
        if (!name || !mobile || !password) {
             console.log('[POST /api/register] Validation FAILED: Missing fields');
             return res.status(400).json({ message: 'Name, mobile, and password are required.' });
        }
        if (!/^[0-9]{10}$/.test(mobile)) {
            console.log('[POST /api/register] Validation FAILED: Mobile not 10 digits.');
            return res.status(400).json({ message: 'Mobile number must be 10 digits.' });
        }

        console.log('[POST /api/register] Step 2: Checking if user exists...');
        const existingUser = await User.findOne({ mobile: mobile });
        if (existingUser) {
            console.log('[POST /api/register] Validation FAILED: User already exists.');
            return res.status(400).json({ message: 'User with this mobile number already exists.' });
        }

        console.log('[POST /api/register] Step 3: Hashing password...');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        console.log('[POST /api/register] Step 4: Creating new user object...');
        const newUser = new User({ name, mobile, password: hashedPassword });

        console.log('[POST /api/register] Step 5: Saving user to database...');
        await newUser.save(); // This might throw validation errors from the schema

        console.log('[POST /api/register] Step 6: User saved! Sending success response.');
        res.status(201).json({ message: 'User registered successfully! Please log in.' });

    } catch (err) {
        // Log the full error for debugging on the server
        console.error('--- REGISTER ERROR ---', err);

        // Send a more specific error message if it's a Mongoose validation error
        if (err.name === 'ValidationError') {
            // Extract a cleaner message from Mongoose error
            const messages = Object.values(err.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        // Send a generic server error message for other errors
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    console.log('[POST /api/login] Received request');
    try {
        const { mobile, password } = req.body;

        if (!mobile || !password) {
            return res.status(400).json({ message: 'Mobile and password are required.' });
        }
         if (!/^[0-9]{10}$/.test(mobile)) {
             console.log('[POST /api/login] Validation FAILED: Invalid mobile format.');
             // Use generic message for security
             return res.status(400).json({ message: 'Invalid mobile number or password.' });
        }

        console.log('[POST /api/login] Step 1: Finding user...');
        const user = await User.findOne({ mobile: mobile });
        if (!user) {
            console.log('[POST /api/login] Auth FAILED: User not found.');
            return res.status(400).json({ message: 'Invalid mobile number or password.' });
        }

        console.log('[POST /api/login] Step 2: Comparing password...');
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
             console.log('[POST /api/login] Auth FAILED: Password incorrect.');
            return res.status(400).json({ message: 'Invalid mobile number or password.' });
        }

        console.log('[POST /api/login] Step 3: Generating token...');
        const payload = { userId: user._id, mobile: user.mobile, name: user.name };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }); // Token expires in 1 day

        console.log('[POST /api/login] Login successful for:', mobile);
        res.status(200).json({ token: token, name: user.name });

    } catch (err) {
        console.error('--- LOGIN ERROR ---', err);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- NEW: RESET PASSWORD ROUTE ---
app.post('/api/reset-password', async (req, res) => {
    console.log('[POST /api/reset-password] Received request');
    try {
        const { mobile, newPassword } = req.body;

        // Basic Validation
        if (!mobile || !newPassword) {
            return res.status(400).json({ message: 'Mobile number and new password are required.' });
        }
        if (!/^[0-9]{10}$/.test(mobile)) {
             return res.status(400).json({ message: 'Mobile number must be 10 digits.' });
        }
        // Add minimum password length validation if desired
        if (newPassword.length < 6) {
             return res.status(400).json({ message: 'Password must be at least 6 characters.' });
        }

        console.log('[POST /api/reset-password] Finding user:', mobile);
        // Find the user by mobile number
        const user = await User.findOne({ mobile: mobile });

        // If user doesn't exist
        if (!user) {
            console.log('[POST /api/reset-password] User not found:', mobile);
            // Send a 404 Not Found status
            return res.status(404).json({ message: 'Account with this mobile number not found.' });
        }

        console.log('[POST /api/reset-password] Hashing new password for user:', user._id);
        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        console.log('[POST /api/reset-password] Updating password in database...');
        // Update the user's password in the database
        user.password = hashedPassword;
        await user.save(); // Save the changes, this will also trigger validation if any

        console.log('[POST /api/reset-password] Password updated successfully for user:', user._id);
        res.status(200).json({ message: 'Password updated successfully!' });

    } catch (err) {
        console.error('--- RESET PASSWORD ERROR ---', err);
        // Handle potential validation errors during save
         if (err.name === 'ValidationError') {
            const messages = Object.values(err.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: 'Server error during password reset.' });
    }
});


// Join Route (Create/Update Worker Profile) - Protected by authMiddleware
app.post('/api/join', authMiddleware, async (req, res) => {
    // req.user is available here from the middleware
    console.log('[POST /api/join] Received request from user:', req.user.userId);
    try {
        const { name, mobile, location, workType } = req.body;
        const userId = req.user.userId; // Get user ID from authenticated token

        // Validation
        if (!name || !mobile || !location || !workType) {
            return res.status(400).json({ message: 'All profile fields (name, mobile, location, workType) are required.' });
        }
        if (!/^[0-9]{10}$/.test(mobile)) {
             return res.status(400).json({ message: 'Mobile number must be 10 digits.' });
        }

        // Use findOneAndUpdate with upsert
        const result = await Worker.findOneAndUpdate(
            { createdBy: userId }, // Find criteria: profile created by this user
            { $set: { name, mobile, location, workType, createdBy: userId } }, // Data to set/update
            { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true, rawResult: true } // Added rawResult: true
        );

        // Check if the operation was successful using rawResult
        if (result.ok) { // Check if the operation was successful
            if (result.lastErrorObject.upserted) {
                // This means a new document was created (upserted)
                console.log('[POST /api/join] Profile created for user:', userId);
                res.status(201).json({ message: 'Profile created successfully!' });
            } else {
                // This means an existing document was updated or matched but not changed
                 console.log('[POST /api/join] Profile updated (or matched) for user:', userId);
                 res.status(200).json({ message: 'Profile updated successfully!' });
            }
        } else {
             // This case indicates a database error during the operation
             console.error('[POST /api/join] DB findOneAndUpdate failed unexpectedly for user:', userId, result);
             res.status(500).json({ message: 'Failed to save profile due to unexpected database error.' });
        }

    } catch (err) {
        console.error('--- JOIN ERROR ---', err);
        if (err.name === 'ValidationError') {
            const messages = Object.values(err.errors).map(val => val.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: 'Server error saving profile.' });
    }
});

// Search Route - Protected by authMiddleware
app.get('/api/search', authMiddleware, async (req, res) => {
    console.log('[GET /api/search] Received request from user:', req.user.userId);
    try {
        const { location, workType } = req.query; // GET requests use req.query for parameters
        let searchQuery = {};

        // Build search query only if parameters are provided
        if (location) {
            // Trim whitespace and use case-insensitive regex
            searchQuery.location = new RegExp(location.trim(), 'i');
        }
        if (workType) {
            searchQuery.workType = workType;
        }

        // Require at least one search parameter
        if (Object.keys(searchQuery).length === 0) {
             console.log('[GET /api/search] Validation FAILED: No search criteria provided.');
             return res.status(400).json({ message: 'Please provide search criteria (location or work type).' });
        }

        console.log('[GET /api/search] Searching with criteria:', searchQuery);
        // Find workers, exclude createdBy and __v fields from the result
        const workers = await Worker.find(searchQuery).select('-createdBy -__v');

        if (workers.length === 0) {
            console.log('[GET /api/search] No workers found.');
            return res.status(404).json({ message: 'No workers found matching your criteria.' });
        }

        console.log(`[GET /api/search] Found ${workers.length} workers.`);
        res.status(200).json(workers); // Send the array of workers

    } catch (err) {
        console.error('--- SEARCH ERROR ---', err);
        res.status(500).json({ message: 'Server error during search.' });
    }
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend server is running on http://localhost:${PORT}`);
    console.log('>>> SERVER LISTENING <<<');
});