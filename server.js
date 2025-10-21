// --- NEW LOG AT VERY TOP ---
console.log('>>> SERVER.JS FILE IS STARTING <<<');

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// --- APP INITIALIZATION ---
const app = express();
app.use(cors()); 
app.use(express.json()); 
console.log('>>> EXPRESS APP INITIALIZED <<<');


// =================================================================
// 1. DATABASE CONNECTION
// =================================================================
const MONGODB_URI = process.env.MONGO_URI; 
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
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    mobile: { type: String, required: true, minlength: 10, maxlength: 10 },
    location: { type: String, required: true },
    workType: { type: String, required: true },
    subWorkType: { type: String, default: '' }
});
const Worker = mongoose.model('Worker', workerSchema);


// =================================================================
// 3. AUTHENTICATION MIDDLEWARE
// =================================================================

const authMiddleware = (req, res, next) => {
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

// REGISTRATION ROUTE (POST /api/register)
app.post('/api/register', async (req, res) => {
    try {
        const { mobile, password, name } = req.body;
        
        if (!mobile || !password || !name) { return res.status(400).json({ message: 'Please provide mobile, password, and name.' }); }

        let user = await User.findOne({ mobile });
        if (user) { return res.status(409).json({ message: 'User with this mobile number already exists.' }); }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ mobile, password: hashedPassword, name });
        await user.save();
        
        const token = jwt.sign({ userId: user._id, name: user.name, mobile: user.mobile }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({ token: token, name: user.name });

    } catch (err) {
        console.error('--- REGISTRATION ERROR ---', err);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// LOGIN ROUTE (POST /api/login)
app.post('/api/login', async (req, res) => {
    try {
        const { mobile, password } = req.body;
        
        const user = await User.findOne({ mobile });
        if (!user) { return res.status(400).json({ message: 'Invalid mobile or password.' }); }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) { return res.status(400).json({ message: 'Invalid mobile or password.' }); }

        const token = jwt.sign({ userId: user._id, name: user.name, mobile: user.mobile }, JWT_SECRET, { expiresIn: '7d' });
        
        res.status(200).json({ token: token, name: user.name });

    } catch (err) {
        console.error('--- LOGIN ERROR ---', err);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// ... existing password reset route ...


// =================================================================
// 5. WORKER ROUTES (JOIN, SEARCH) - Requires authMiddleware
// =================================================================

// JOIN ROUTE (POST /api/join) - Protected
app.post('/api/join', authMiddleware, async (req, res) => {
    try {
        const { name, mobile, location, workType, subWorkType } = req.body; 
        const createdBy = req.user.userId;

        let worker = await Worker.findOne({ createdBy });
        
        if (worker) {
            worker.name = name;
            worker.mobile = mobile;
            worker.location = location;
            worker.workType = workType;
            worker.subWorkType = subWorkType; 
        } else {
            worker = new Worker({ createdBy, name, mobile, location, workType, subWorkType }); 
        }
        
        await worker.save();
        res.status(201).json({ message: 'Worker profile created/updated successfully.' });

    } catch (err) {
        if (err.code === 11000) { return res.status(409).json({ message: 'A worker profile already exists for this user ID.' }); }
        console.error('--- JOIN WORKER ERROR ---', err);
        res.status(500).json({ message: 'Server error saving worker profile.' });
    }
});

// SEARCH ROUTE (GET /api/search) - Protected
app.get('/api/search', authMiddleware, async (req, res) => {
    try {
        const { location, workType, subWorkType } = req.query; 
        let searchQuery = {};

        // 1. LOCATION search (Case-insensitive)
        if (location) { searchQuery.location = new RegExp(location, 'i'); }
        
        // 2. WORK TYPE search (Case-insensitive)
        if (workType && workType !== 'all') { 
            searchQuery.workType = new RegExp(workType, 'i'); // <-- FIX: Use case-insensitive RegExp
        }
        
        // 3. SUB-WORK TYPE search (Case-insensitive)
        if (subWorkType && subWorkType !== 'all' && subWorkType !== '') { 
            searchQuery.subWorkType = new RegExp(subWorkType, 'i'); // <-- FIX: Use case-insensitive RegExp
        }

        if (Object.keys(searchQuery).length === 0) {
              return res.status(400).json({ message: 'Please provide search criteria (location, work type, or specialty).' });
        }
        
        const workers = await Worker.find(searchQuery).select('name mobile location workType subWorkType -createdBy -__v');

        if (workers.length === 0) {
            return res.status(404).json({ message: 'No workers found matching your criteria.' });
        }

        res.status(200).json(workers); 

    } catch (err) {
        // This is the error handler that caught the 500. Log the full error for debugging.
        console.error('--- SEARCH ERROR TRACE ---', err.stack || err.message);
        res.status(500).json({ message: 'Server error during search.' });
    }
});


// =================================================================
// 6. SERVER STARTUP
// =================================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Backend server is running on port ${PORT}`);
    console.log('>>> SERVER LISTENING... <<<');
});
