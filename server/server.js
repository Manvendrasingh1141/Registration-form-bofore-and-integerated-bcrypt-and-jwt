import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const SECRET_KEY = 'super_secret_key_for_rbac';

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../client/dist')));

// Dummy users (passwords are hashed for demonstration purposes)
const users = [
    { username: 'admin', password: bcrypt.hashSync('admin123', 10), role: 'admin', name: 'Super Admin' },
    { username: 'user', password: bcrypt.hashSync('user123', 10), role: 'user', name: 'Regular User' }
];

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid token.' });
        req.user = decoded;
        next();
    });
};

app.post('/api/signup', async (req, res) => {
    const { username, password, name, role } = req.body;

    if (!username || !password || !name || !role) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'Username already exists.' });
    }

    if (role !== 'admin' && role !== 'user') {
        return res.status(400).json({ message: 'Invalid role selection.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { username, password: hashedPassword, name, role };
        users.push(newUser);
        res.status(201).json({ message: 'User created successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Error creating user.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ message: 'Username, password, and role are required.' });
    }

    const user = users.find(u => u.username === username);

    if (user && user.role === role) {
        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                const token = jwt.sign({ username: user.username, role: user.role, name: user.name }, SECRET_KEY, { expiresIn: '1h' });
                return res.json({ token, role: user.role, name: user.name });
            }
        } catch (err) {
            return res.status(500).json({ message: 'Error during authentication.' });
        }
    }

    return res.status(401).json({ message: 'Invalid credentials or role mismatch.' });
});

// Example of a protected route
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.name}, you have access to this protected data as a ${req.user.role}.` });
});

// Catch-all route to serve the React app for unrecognized routes (client-side routing)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/dist/index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
