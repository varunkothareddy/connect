// --- NEW LOG AT VERY TOP ---
console.log('>>> SERVER.JS FILE IS STARTING <<<');

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// --- APP INITIALIZATION ---
const app = express();
app.use(cors()); // Allow all origins for simplicity in development
app.use(express.json()); // Middleware to parse JSON bodies
console.log('>>> EXPRESS APP INITIALIZED <<<');


// =================================================================
// 1. DATABASE CONNECTION
// =================================================================
const MONGODB_URI = process.env.MONGO_URI; 
// *** IMPORTANT: Set a strong, unique value for JWT_SECRET in your Render environment variables. ***
const JWT_SECRET = process.env.JWT_SECRET || 'your_default_secret_key'; 

if (!MONGODB_URI) {
    console.error('FATAL ERROR: MONGO_URI is not defined in Render Environment Variables.');
    process.exit(1); 
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('>>> MONGODB CONNECTED SUCCESSFULLY! <<<'))
    .catch(err => {
        console.error('FATAL ERROR: MONGODB CONNECTION FAILED:', err.message);
        process.exit(1);
    });

// =================================================================
// 2. MONGOOSE SCHEMAS & MODELS
// =================================================================

// Schema for authenticated users (Client/Worker who logs in)
const userSchema = new mongoose.Schema({
    mobile: { type: String, required: true, unique: true, minlength: 10, maxlength: 10 },
    password: { type: String, required: true },
    name: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Schema for Worker Profiles (The data created via join.html)
const workerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    mobile: { type: String, required: true, minlength: 10, maxlength: 10 },
    location: { type: String, required: true },
    workType: { type: String, required: true } // e.g., plumber, electrician
});
const Worker = mongoose.model('Worker', workerSchema);


// =================================================================
// 3. AUTHENTICATION MIDDLEWARE
// =================================================================

const authMiddleware = (req, res, next) => {
    // Check for token in 'Authorization: Bearer <token>' header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'Access Denied: No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (ex) {
        console.log('JWT Verification Failed:', ex.message);
        res.status(400).json({ message: 'Invalid token.' });
    }
};


// =================================================================
// 4. AUTHENTICATION ROUTES (LOGIN, REGISTER)
// =================================================================

// 🚀 CRITICAL FIX: REGISTRATION ROUTE (POST /api/register)
app.post('/api/register', async (req, res) => {
    try {
        const { mobile, password, name } = req.body;
        
        // Basic Validation
        if (!mobile || !password || !name) {
            return res.status(400).json({ message: 'Please provide mobile, password, and name.' });
        }
        if (mobile.length !== 10) {
             return res.status(400).json({ message: 'Mobile number must be 10 digits.' });
        }

        // Check if user already exists
        let user = await User.findOne({ mobile });
        if (user) {
            console.log('[POST /api/register] FAILED: User already exists for mobile:', mobile);
            return res.status(409).json({ message: 'User with this mobile number already exists.' });
        }

        // Create new user
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ mobile, password: hashedPassword, name });
        await user.save();
        
        // Generate and send token
        const token = jwt.sign({ _id: user._id, name: user.name, mobile: user.mobile }, JWT_SECRET, { expiresIn: '7d' });

        console.log('[POST /api/register] SUCCESS: New user registered:', user.name);
        res.status(201).json({ token, user: { name: user.name, mobile: user.mobile } });

    } catch (err) {
        console.error('--- REGISTRATION ERROR ---', err);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// LOGIN ROUTE (POST /api/login)
app.post('/api/login', async (req, res) => {
    try {
        const { mobile, password } = req.body;
        if (!mobile || !password) {
            return res.status(400).json({ message: 'Please provide mobile and password.' });
        }

        const user = await User.findOne({ mobile });
        if (!user) {
            return res.status(400).json({ message: 'Invalid mobile or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid mobile or password.' });
        }

        const token = jwt.sign({ _id: user._id, name: user.name, mobile: user.mobile }, JWT_SECRET, { expiresIn: '7d' });
        
        console.log('[POST /api/login] SUCCESS:', user.name);
        res.status(200).json({ token, user: { name: user.name, mobile: user.mobile } });

    } catch (err) {
        console.error('--- LOGIN ERROR ---', err);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// PASSWORD RESET ROUTE (POST /api/reset-password)
app.post('/api/reset-password', async (req, res) => {
    try {
        const { mobile, newPassword } = req.body;
        
        if (!mobile || !newPassword) {
            return res.status(400).json({ message: 'Please provide mobile and a new password.' });
        }

        const user = await User.findOne({ mobile });
        if (!user) {
            return res.status(404).json({ message: 'User not found with this mobile number.' });
        }
        
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        
        console.log('[POST /api/reset-password] SUCCESS for mobile:', mobile);
        res.status(200).json({ message: 'Password updated successfully.' });

    } catch (err) {
        console.error('--- RESET PASSWORD ERROR ---', err);
        res.status(500).json({ message: 'Server error during password reset.' });
    }
});


// =================================================================
// 5. WORKER ROUTES (JOIN, SEARCH) - Requires authMiddleware
// =================================================================

// JOIN ROUTE (POST /api/join) - Protected
app.post('/api/join', authMiddleware, async (req, res) => {
    try {
        const { name, mobile, location, workType } = req.body;
        const userId = req.user._id; // Extracted from JWT by authMiddleware

        // Check if a worker profile already exists for this user
        let worker = await Worker.findOne({ userId });
        if (worker) {
            console.log(`[POST /api/join] Worker profile already exists for user ${userId}. Updating profile.`);
            // Update existing profile instead of creating a new one
            worker.name = name;
            worker.mobile = mobile;
            worker.location = location;
            worker.workType = workType;
        } else {
            // Create a new worker profile
            worker = new Worker({ userId, name, mobile, location, workType });
        }
        
        await worker.save();
        console.log(`[POST /api/join] Worker profile saved for user ${name}.`);
        res.status(201).json({ message: 'Worker profile created/updated successfully.' });

    } catch (err) {
        console.error('--- JOIN WORKER ERROR ---', err);
        // Handle MongoDB duplicate key error (mobile field)
        if (err.code === 11000) {
            return res.status(409).json({ message: 'A worker profile already exists for this user ID.' });
        }
        res.status(500).json({ message: 'Server error saving worker profile.' });
    }
});

// SEARCH ROUTE (GET /api/search) - Protected
app.get('/api/search', authMiddleware, async (req, res) => {
    try {
        const { location, workType } = req.query;
        let searchQuery = {};

        if (location) {
            // Case-insensitive search for location
            searchQuery.location = new RegExp(location, 'i');
        }
        if (workType && workType !== 'all') { // Assume 'all' is an option to search by location only
            searchQuery.workType = workType.toLowerCase();
        }
        
        if (Object.keys(searchQuery).length === 0) {
              console.log('[GET /api/search] Validation FAILED: No search criteria provided.');
              return res.status(400).json({ message: 'Please provide search criteria (location or work type).' });
        }

        console.log('[GET /api/search] Searching with criteria:', searchQuery);
        // Exclude sensitive internal fields
        const workers = await Worker.find(searchQuery).select('-userId -__v');

        if (workers.length === 0) {
            console.log('[GET /api/search] No workers found.');
            return res.status(404).json({ message: 'No workers found matching your criteria.' });
        }

        console.log(`[GET /api/search] Found ${workers.length} workers.`);
        res.status(200).json(workers); 

    } catch (err) {
        console.error('--- SEARCH ERROR ---', err);
        res.status(500).json({ message: 'Server error during search.' });
    }
});


// =================================================================
// 6. SERVER STARTUP
// =================================================================
// Use the port provided by Render (process.env.PORT) or fallback to 3000 locally
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Backend server is running on port ${PORT}`);
    console.log('>>> SERVER LISTENING... <<<');
});
