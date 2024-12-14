//do npm install when download 

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const session = require('express-session');
const bodyParser = require('body-parser');
const db = require('./connector'); // Import the database connection
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const secretKey = process.env.secretKey; // Keep this secret and secure

const adminRoutes = require('./adminRoutes');



const app = express();
const port = process.env.PORT || 3000;

app.use(session({
    secret: 'Nischay@0409', // Replace with a secure random string
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Middleware
app.use(express.static('public'));
app.use('/public', express.static(path.join(__dirname, 'public')));

app.use('/admin', express.static(path.join(__dirname, 'public', 'Admin')));
app.use('/user', express.static(path.join(__dirname, 'public', 'User')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Serve static files from L&F directory
app.use('/L&F', express.static(path.join(__dirname)));
app.use('/L&F', express.static(path.join(__dirname, 'L&F')));







// If you're using express built-in middleware (from Express 4.16+):
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Format date to dd-mm-yyyy
function formatDate(date) {
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
    const year = date.getFullYear();
    return `${day}-${month}-${year}`;
}
 //  current time to IST
 function formatToIST() {
    return moment().tz("Asia/Kolkata").format('YYYY-MM-DD HH:mm:ss'); // You can change the format as needed
}


const moment = require('moment-timezone');

// User Registration route
app.post('/register', async (req, res) => {
    const { name, phone_no, email, address, password } = req.body;

    // Check if the user already exists
    const checkUserSql = 'SELECT * FROM user WHERE email = ?';
    console.log('Executing SQL:', checkUserSql, [email]); // Debug log
    db.query(checkUserSql, [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }

        if (results.length > 0) {
            // User already exists, send a failure response
            return res.json({ success: false, message: 'User already exists. Try logging in.' });
        } else {
            try {
                // Hash the password using bcrypt
                const hashedPassword = await bcrypt.hash(password, 10);

                // Store only relative path
                const relativeFolderPath = `uploads/${name}_${formatDate(new Date())}`;
                const fullFolderPath = path.join(__dirname, relativeFolderPath);

                // Create user folder using the full path
                fs.mkdirSync(fullFolderPath, { recursive: true });

                // Get current time in IST
                const created_at = formatToIST();
                console.log('Created at:', created_at);

                // Insert new user into the database
                const sql = 'INSERT INTO user (name, phone_no, email, address, password, folder_path, created_at, allowance) VALUES (?, ?, ?, ?, ?, ?, ?,3)';
                db.query(sql, [name, phone_no, email, address, hashedPassword, relativeFolderPath, created_at], (err, result) => {
                    if (err) {
                        return res.status(500).json({ success: false, message: err.message });
                    }

                    // Retrieve the inserted user ID
                    const userId = result.insertId;
                    console.log('New user ID:', userId);

                    // Store user ID in the session
                    req.session.userId = userId; // Store user ID in session

                    res.json({ success: true, message: 'User registered successfully!' });
                });
            } catch (error) {
                return res.status(500).json({ success: false, message: 'Error hashing password or creating folder.' });
            }
        }
    });
});


// User Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Check if the user exists
    const sql = 'SELECT * FROM user WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: 'Invalid credentials.' });
        }

        const user = results[0];

        // Compare password with hashed password stored in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.json({ success: false, message: 'Invalid credentials.' });
        }

        // Log the user ID upon successful login
        console.log('User ID:', user.id);

        // Store user ID in the session
        req.session.userId = user.id; // Store user ID in session

        // Redirect to user home after login
        res.json({ success: true, message: 'Login successful.', folderPath: user.folder_path, redirectUrl: '/User/home.html' });
    });
});




app.post('/admin/register', async (req, res) => {
    const { police_station_name, station_email, address, pincode, password } = req.body;
    const username = `${police_station_name}_${pincode}`; // Create unique username
    const folderPath = path.join('L&F', 'Admin', `${police_station_name}_${pincode}`);

    try {
        // Create the folder structure if it doesn't exist
        fs.mkdirSync(folderPath, { recursive: true });

        // Hash the password before storing
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new admin record into the database, including the folder path
        const sql = 'INSERT INTO admin (police_station_name, station_email, address, pincode, username, password, folder_path) VALUES (?, ?, ?, ?, ?, ?, ?)';
        db.query(sql, [police_station_name, station_email, address, pincode, username, hashedPassword, folderPath], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'Admin with this username already exists' });
                }
                console.error("Database insert error:", err);
                return res.status(500).json({ message: 'Error registering admin' });
            }
            

            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL_USER, // Use environment variable
                    pass: process.env.EMAIL_PASS, // Use environment variable
                },
            });

            // Define the email options
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: station_email,
                subject: 'Congratulations on Your Admin Registration!',
                text: `Hello ${police_station_name} (Police Station),\n\nYour admin registration was successful!\n\nUsername: ${username}\n\nYou can now log in using this username.\n\nBest regards,\nThe Team`
            };

            // Send the email
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email:', error);
                    return res.status(500).json({ message: 'Admin registered, but email sending failed.' });
                } else {
                    res.status(201).json({ message: 'Admin registered successfully and confirmation email sent!' });
                }
            });
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: 'Error registering admin' });
    }
});
// Admin Login

app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Fetch admin details from the database
        const sql = 'SELECT id, password FROM admin WHERE username = ?';
        db.query(sql, [username], async (err, results) => {
            if (err || results.length === 0) {
                return res.status(400).json({ message: 'Invalid username or password' });
            }

            const admin = results[0];
            const isPasswordValid = await bcrypt.compare(password, admin.password);

            if (!isPasswordValid) {
                return res.status(400).json({ message: 'Invalid username or password' });
            }

            // Generate JWT token
            const token = jwt.sign({ id: admin.id, username }, secretKey, { expiresIn: '1h' });
            req.session.adminId = admin.id;
            console.log("Admin Id:",req.session.adminId);
            // Redirect to admin dashboard after login
            res.status(200).json({ message: 'Login successful', token, redirectUrl: '/admin/dashboard' });
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: 'Error during login' });
    }
});


// Serve admin dashboard page
app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Admin', 'dashboard.html')); 
});

app.get('/admin/user_info', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Admin', 'user_info.html'), (err) => {
        if (err) {
            console.error("File not found:", err);
            res.status(err.status).send('File not found');
        }
    });
});



// Fetch all verified users
app.get('/admin/users/verified', (req, res) => {
    const sql = 'SELECT id, name FROM user WHERE validate = 1';
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).send(err.message);
        }
        res.json(results);
    });
});

// Fetch all non-verified users
app.get('/admin/users/non-verified', (req, res) => {
    const sql = 'SELECT id, name FROM user WHERE validate IS NULL OR validate = 0;';
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).send(err.message);
        }
        res.json(results);
    });
});

// Fetch details for a specific user
app.get('/admin/user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'SELECT name, email, phone_no, address, folder_path, created_at FROM user WHERE id = ?';

    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).send(err.message);

        if (results.length > 0) {
            const user = results[0];
            const formattedDate = new Date(user.created_at).toLocaleString('en-IN', {
                timeZone: 'Asia/Kolkata',
                hour12: true, // Change to false for 24-hour format
            });

            const relativeFolderPath = user.folder_path;
            const fullFolderPath = path.join(__dirname, relativeFolderPath);

            fs.readdir(fullFolderPath, { withFileTypes: true }, (err, files) => {
                if (err) {
                    console.error('Error reading directory:', err);
                    return res.status(500).send(err.message);
                }

                const subfolders = files
                    .filter(file => file.isDirectory())
                    .map(folder => folder.name);

                res.json({
                    userDetails: {
                        ...user,
                        created_at: formattedDate, // Set the formatted date
                    },
                    folderPath: fullFolderPath,
                    subfolders: subfolders,
                });
            });
        } else {
            res.status(404).send('User not found');
        }
    });
});

// Fetch user details
app.get('/user/details', (req, res) => {
    const userId = req.session.userId; // Get the logged-in user's ID from the session
    
    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const sql = 'SELECT name, email, phone_no, address FROM user WHERE id = ?';
    db.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error fetching user details', error: err });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: 'No user details found.' });
        }

        res.json({ success: true, user: results[0] }); // Return the first user record
    });
});


// Function OF Web

app.get('/user_info.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'User', 'user_info.html'), (err) => {
        if (err) {
            console.error("File not found:", err);
            res.status(err.status).send('File not found');
        }
    });
});
require('dotenv').config(); // Load environment variables

// User Update route
app.post('/user/update', (req, res) => {
    const userId = req.session.userId; // Get the logged-in user's ID from the session
    const { name, phone_no, email, address } = req.body; // Destructure the data from the request body

    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not authenticated.' });
    }

    // Get the current time in IST for created_at field
    const created_at = formatToIST();

    // Update user details and the created_at timestamp in the database
    const sql = 'UPDATE user SET name = ?, phone_no = ?, email = ?, address = ?, created_at = ? ,validate=0 WHERE id = ?';
    db.query(sql, [name, phone_no, email, address, created_at, userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error updating user details.', error: err.message });
        }

        if (result.affectedRows === 0) {
            return res.json({ success: false, message: 'No user found to update.' });
        }

        res.json({ success: true, message: 'User details and timestamp updated successfully!' });
    });
});

// Send OTP to email
app.post('/send-otp', async (req, res) => {
    const userId = req.session.userId; // Get the logged-in user's ID from the session

    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    const sql = 'SELECT email FROM user WHERE id = ?';
    db.query(sql, [userId], async (err, results) => {
        if (err) {
            console.error('Error fetching user details:', err); // Log the error
            return res.status(500).json({ success: false, message: 'Error fetching user details', error: err.message });
        }

        if (results.length === 0) {
            return res.json({ success: false, message: 'No user details found.' });
        }

        const email = results[0].email;
        const otp = crypto.randomInt(100000, 999999); // Generate a random 6-digit OTP

        // Set up nodemailer
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER, // Use environment variable
                pass: 'eacfkmfocqezrvpn', // Use environment variable
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER, // Use environment variable for sender email
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is here to validate the email: ${otp}. Avail the feature of the web.`,
        };

        // Send email
        try {
            await transporter.sendMail(mailOptions);
            req.session.otp = otp; // Store OTP in session for later verification
            res.json({ success: true, message: 'OTP sent to your email!' });
        } catch (error) {
            console.error('Error sending OTP email:', error); // Log the error
            res.status(500).json({ success: false, message: 'Error sending OTP', error: error.message });
        }
    });
});

// Verify OTP
app.post('/verify-otp', (req, res) => {
    const { otp } = req.body; // Get OTP from the request body
    const userId = req.session.userId; // Get the logged-in user's ID from the session

    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not authenticated' });
    }

    if (otp == req.session.otp) {
        // Update validate column in the database
        const sql = 'UPDATE user SET validate = ? WHERE id = ?';
        db.query(sql, [true, userId], (err, result) => {
            if (err) {
                console.error('Error updating user validation:', err); // Log the error
                return res.status(500).json({ success: false, message: 'Error updating user validation', error: err.message });
            }

            res.json({ success: true, message: 'Email verified successfully!' });
        });
    } else {
        res.status(400).json({ success: false, message: 'Invalid OTP. Please try again.' });
    }
});



//Evidence Upload 

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        res.status(401).json({ message: "Unauthorized access" });
    }
}

// Route to check if the user is validated
app.get('/check-validation', isAuthenticated, (req, res) => {
    const userId = req.session.userId; // Assuming user ID is stored in session

    const sql = 'SELECT validate FROM user WHERE id = ?';
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Internal Server Error" });
        }

        if (result.length > 0 && (result[0].validate === 1 || result[0].validate === true)) {
            res.json({ isValidated: true });
        } else {
            res.json({ isValidated: false });
        }
    });
});

// Route to serve add_evidence.html if validated
app.get('/user/add_evidence.html', isAuthenticated, (req, res) => {
    const userId = req.session.userId;

    const sql = 'SELECT validate FROM user WHERE id = ?';
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Internal Server Error");
        }

        if (result.length > 0 && (result[0].validate === 1 || result[0].validate === true)) {
            res.sendFile(__dirname + '/public/user/add_evidence.html'); // Serve the add_evidence.html page
        } else {
            res.status(403).send("Access denied: You are not validated.");
        }
    });
});





const upload = multer({ dest: 'uploads/' });

// Endpoint for file upload
app.post('/upload', upload.single('file'), (req, res) => {
    if (req.file) {
        res.json({ success: true, message: 'File uploaded successfully', filePath: req.file.path });
    } else {
        res.json({ success: false, message: 'File upload failed' });
    }
});


app.post('/submit_evidence', upload.any(), (req, res) => {
    const userId = req.session.userId; // Get user ID from session
    const evidenceType = req.body.activity_type; // Get the evidence type
    const description = req.body.description; // Get the description
    const uploadDate = new Date(); // Current upload date
    const location = req.body.manualLocation || `${req.body.latitude}, ${req.body.longitude}`; // Get location

    // Retrieve the user's folder path from the database
    db.query('SELECT folder_path FROM user WHERE id = ?', [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }

        // Check if the user exists and has a folder path
        if (results.length === 0 || !results[0].folder_path) {
            return res.status(404).json({ success: false, message: 'User folder not found.' });
        }

        const userFolderPath = results[0].folder_path; // Get the user's folder path
        const evidenceFolderName = `${evidenceType}_${formatDate(uploadDate)}`;
        const evidenceFolderPath = path.join(userFolderPath, evidenceFolderName); // Full path for the evidence folder

        // Create the evidence folder if it doesn't exist
        fs.mkdirSync(evidenceFolderPath, { recursive: true });

        // Query to get the count of existing records with the same evidence_type to create a unique id
        const countQuery = `
            SELECT COUNT(*) AS count FROM uploads
            WHERE evidence_type = ?
        `;

        db.query(countQuery, [evidenceType], (err, countResult) => {
            if (err) {
                return res.status(500).json({ success: false, message: err.message });
            }

            // Generate a unique id by appending the count to the evidence_type
            const count = countResult[0].count + 1; // Increment count to avoid using 0
            const uniqueId = `${evidenceType}_${count}`;

            // Process and store file paths in a JSON array
            const files = req.files;
            if (files && files.length > 0) {
                const filePaths = files.map((file, index) => {
                    // Generate a new filename using evidence_type, unique id, and index
                    const newFileName = `${uniqueId}_${index + 1}${path.extname(file.originalname)}`;
                    const destinationPath = path.join(evidenceFolderPath, newFileName);

                    // Move the file to the evidence folder with the new name
                    fs.renameSync(file.path, destinationPath);
                    
                    // Construct relative path for each file
                    const relativeFilePath = path.join(evidenceFolderName, newFileName);
                    return relativeFilePath;
                });

                // Insert evidence record into the database with the unique id and JSON array for file_path
                const sql = 'INSERT INTO uploads (id, user_id, evidence_type, file_path, upload_date, description, location) VALUES (?, ?, ?, ?, ?, ?, ?)';
                db.query(sql, [uniqueId, userId, evidenceType, JSON.stringify(filePaths), uploadDate, description, location], (err, result) => {
                    if (err) {
                        console.error('Database insert error:', err);
                        return res.status(500).json({ success: false, message: err.message });
                    }

                    res.json({ success: true, message: 'Evidence uploaded successfully!', redirectUrl: '/User/home.html' });
                });
            } else {
                return res.status(400).json({ success: false, message: 'No files were uploaded.' });
            }
        });
    });
});
 

app.use('/admin', adminRoutes);

// Serve evidence.html
app.get('/evidence.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Admin', 'evidence.html'), (err) => {
        if (err) {
            console.error("File not found:", err);
            res.status(err.status).send('File not found');
        }
    });
});


// Updated route to fetch evidence data
app.get('/admin/getEvidence', (req, res) => {
    const crimeType = req.query.crimeType;
    const investigated = req.query.investigated === 'investigated' ? 1 : 0; // 1 for investigated, 0 for non-investigated

    const sql = `
        SELECT u.name AS username, u.email, up.location AS location, 
               up.description, up.upload_date, up.file_path, 
               up.evidence_type, up.verified, up.user_id AS user_id
        FROM uploads up
        JOIN user u ON up.user_id = u.id
        WHERE LOWER(up.evidence_type) = LOWER(?) AND up.verified = ?
    `;

    db.query(sql, [crimeType, investigated], (error, results) => {
        if (error) {
            console.error("Database error:", error);
            return res.status(500).json({ error: error.message });
        }
        res.json(results);
    });
});




function formatDateForDB(dateString) {
    // console.log("Original date string:", dateString);

    // Check if dateString is provided, if not return null
    if (!dateString) {
        console.error("Date string is undefined or null:", dateString);
        return null;
    }

    // Try creating a Date object from the dateString
    const date = new Date(dateString);

    // Check if the date is valid
    if (isNaN(date)) {
        console.error("Invalid date format:", dateString);
        return null; // Return null or handle the error as needed
    }

    // Extract year, month, day, hours, minutes, and seconds
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0'); // Month is 0-indexed, so we add 1
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    // Return formatted date in the desired format 'YYYY-MM-DD HH:MM:SS'
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}
app.get('/admin/getUserUploads', (req, res) => {
    const userId = req.query.user_id;
    const evidenceType = req.query.evidence_type;
    const uploadDate = req.query.upload_date;

    //console.log("Fetching uploads for user ID:", userId, "and evidence type:", evidenceType, "and upload date:", uploadDate);

    // Format the upload date for database if provided
    const formattedUploadDate = uploadDate ? formatDateForDB(uploadDate) : null;

    // Query to retrieve the base folder path from the `user` table
    const userQuery = `SELECT folder_path FROM user WHERE id = ?`;

    db.query(userQuery, [userId], (userError, userResults) => {
        if (userError || userResults.length === 0) {
            console.error("User folder not found or error:", userError);
            return res.status(500).json({ error: 'User folder not found.' });
        }

        const userFolderPath = userResults[0].folder_path;

        // Query to find uploads based on user_id, evidence_type, and upload_date
        const uploadQuery = `
            SELECT id, file_path, evidence_type, upload_date 
            FROM uploads 
            WHERE user_id = ? AND upload_date = ? AND evidence_type = ?
        `;

        const queryParams = [userId, formattedUploadDate, evidenceType];

        db.query(uploadQuery, queryParams, (uploadError, uploadResults) => {
            if (uploadError) {
                console.error("Error fetching uploads:", uploadError);
                return res.status(500).json({ error: uploadError.message });
            }

            //console.log("Upload results:", uploadResults);

            if (uploadResults.length === 0) {
                console.log("No uploads found for this user.");
                return res.json({ files: [] });
            }

            // No need to parse file_path; directly access it as an array
            const files = uploadResults.flatMap(upload => {
                const filePaths = upload.file_path; // Already JSON in DB, no need to parse
                return filePaths.map(filePath => ({
                    upload_id: upload.id,
                    full_path: `/${userFolderPath}/${filePath.trim().replace(/\\/g, '/')}`,
                    evidence_type: upload.evidence_type,
                    upload_date: upload.upload_date
                }));
            });

            //console.log("Final files array:", files);
            res.json(files);
        });
    });
});


/// Endpoint to delete an evidence folder
app.delete('/admin/deleteFolder', (req, res) => {
    const userId = req.query.user_id; // Get the user ID from the request query
    const evidenceType = req.query.evidence_type; // Get the evidence type from the request query

    console.log("Deleting uploads for user ID:", userId, "and evidence type:", evidenceType);

    // Query to retrieve the base folder path from the `user` table
    const userQuery = `SELECT folder_path FROM user WHERE id = ?`;
    
    db.query(userQuery, [userId], (userError, userResults) => {
        if (userError || userResults.length === 0) {
            console.error("User folder not found or error:", userError);
            return res.status(500).json({ error: 'User folder not found.' });
        }

        const userFolderPath = userResults[0].folder_path;

        // Query to retrieve the file path(s) and id from the `uploads` table for the specified evidence type
        const filePathQuery = `SELECT id, file_path FROM uploads WHERE user_id = ? AND evidence_type = ?`;
        
        db.query(filePathQuery, [userId, evidenceType], (fileError, fileResults) => {
            if (fileError || fileResults.length === 0) {
                console.error("File path not found or error:", fileError);
                return res.status(500).json({ error: 'File path not found.' });
            }

            // Retrieve the id and file paths from the query result
            const uploadId = fileResults[0].id;
            const filePaths = fileResults[0].file_path;

            // Extract the folder name from the first file path, e.g., "Vandalism_05-11-2024"
            const folderName = filePaths[0].split('/')[0];

            // Construct the full folder path to delete
            const folderPathToDelete = path.join(__dirname, userFolderPath, folderName);
            console.log("Full folder path to delete:", folderPathToDelete);

            // Check if the folder exists and delete it
            if (fs.existsSync(folderPathToDelete)) {
                fs.rm(folderPathToDelete, { recursive: true, force: true }, (err) => {
                    if (err) {
                        console.error('Error deleting folder:', err);
                        return res.status(500).json({ error: 'Failed to delete evidence folder.' });
                    }
                    console.log('Evidence folder deleted successfully.');

                    // After successful folder deletion, delete all corresponding entries in the database for the user and evidence type
                    const deleteQuery = `DELETE FROM uploads WHERE user_id = ? AND evidence_type = ?`;
                    
                    db.query(deleteQuery, [userId, evidenceType], (deleteError, deleteResults) => {
                        if (deleteError) {
                            console.error("Error deleting evidence records from database:", deleteError);
                            return res.status(500).json({ error: 'Failed to delete evidence records from database.' });
                        }
                        console.log('Evidence records deleted from database successfully.');
                        res.json({ message: 'Evidence folder and all corresponding records deleted successfully.' });
                    });
                });
            } else {
                console.log("Evidence folder does not exist.");
                return res.status(404).json({ error: 'Evidence folder not found.' });
            }
        });
    });
});


// Route to delete all files within an upload and the associated row in the uploads table
app.delete('/admin/deleteEvidenceFile', (req, res) => {
    const { user_id, evidence_type, upload_date } = req.query;

    if (!user_id || !evidence_type || !upload_date) {
        return res.status(400).json({ error: 'Missing required parameters.' });
    }

    const formattedUploadDate = formatDateForDB(upload_date);

    // Step 1: Get the user-specific folder path
    db.query('SELECT folder_path FROM user WHERE id = ?', [user_id], (err, userResults) => {
        if (err) {
            console.error("Error finding user folder path:", err);
            return res.status(500).json({ error: 'Failed to retrieve user folder path.' });
        }

        if (userResults.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const userFolderPath = userResults[0].folder_path;

        // Step 2: Get file paths from the uploads table
        db.query(
            'SELECT file_path, id, evidence_type, upload_date FROM uploads WHERE user_id = ? AND evidence_type = ? AND upload_date = ?',
            [user_id, evidence_type, formattedUploadDate],
            (err, uploadResults) => {
                if (err) {
                    console.error("Error finding evidence record:", err);
                    return res.status(500).json({ error: 'Failed to find evidence record.' });
                }

                if (uploadResults.length === 0) {
                    return res.status(404).json({ error: 'Evidence record not found.' });
                }

                // Step 3: Map through the file_path array and construct full paths
                const files = uploadResults.flatMap(upload => {
                    // file_path is already a JSON array in the DB
                    const filePaths = upload.file_path; // No need to parse, directly access it as an array
                    
                    return filePaths.map(filePath => {
                        // Construct the full file path by joining the user folder path and the file path
                        const fullFilePath = path.join(__dirname, userFolderPath, filePath.trim().replace(/\\/g, '/'));
                        return {
                            upload_id: upload.id,
                            full_path: fullFilePath,  // Full path to delete the file
                            evidence_type: upload.evidence_type,
                            upload_date: upload.upload_date
                        };
                    });
                });

                // Step 4: Delete each file in the file paths array
                const deletePromises = files.map(file => {
                    return new Promise((resolve, reject) => {
                        // Check if the file exists before attempting to delete
                        fs.access(file.full_path, fs.constants.F_OK, (err) => {
                            if (err) {
                                // If the file doesn't exist, log an error and continue with other files
                                console.error(`File not found: ${file.full_path}`);
                                reject(new Error(`File not found: ${file.full_path}`));
                            } else {
                                // File exists, proceed to delete
                                fs.unlink(file.full_path, (err) => {
                                    if (err) {
                                        console.error(`Error deleting file ${file.full_path}:`, err);
                                        reject(err);
                                    } else {
                                        resolve();
                                    }
                                });
                            }
                        });
                    });
                });

                // Execute all delete file promises
                Promise.all(deletePromises)
                    .then(() => {
                        // Step 5: Delete the database row from the uploads table
                        db.query(
                            'DELETE FROM uploads WHERE user_id = ? AND evidence_type = ? AND upload_date = ?',
                            [user_id, evidence_type, formattedUploadDate],
                            (error) => {
                                if (error) {
                                    console.error("Error deleting database entry:", error);
                                    return res.status(500).json({ error: 'Failed to delete evidence record from the database.' });
                                }
                                res.json({ message: 'Evidence record and all associated files deleted successfully.' });
                            }
                        );
                    })
                    .catch((error) => {
                        console.error("Error deleting files:", error);
                        res.status(500).json({ error: 'Failed to delete one or more evidence files.' });
                    });
            }
        );
    });
});
// New route to mark evidence as investigated
app.post('/admin/investigateEvidence', (req, res) => {
   const { user_id, evidence_type, upload_date } = req.query;

    if (!user_id || !evidence_type || !upload_date) {
        return res.status(400).json({ error: 'Missing required parameters.' });
    }

    const formattedUploadDate = formatDateForDB(upload_date);

    const sql = `
        UPDATE uploads 
        SET verified = 1 
        WHERE user_id = ?  AND evidence_type = ? AND upload_date = ? AND verified = 0
    `;

    db.query(sql, [user_id, evidence_type, formattedUploadDate], (error, result) => {
        if (error) {
            console.error("Database error:", error);
            return res.status(500).json({ error: "Database update failed." });
        }
        res.json({ success: result.affectedRows > 0 });
    });
});

// Route to warn user
app.post('/admin/warnUser', (req, res) => {
    const userId = req.query.user_id; // Assuming you're sending the user_id as a query parameter

    // Update allowance in the database
    const query = 'UPDATE user SET allowance = allowance - 1 WHERE id = ?';

    db.query(query, [userId], async (error, results) => {
        if (error) {
            console.error("Database error:", error);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        // Fetch updated allowance and email in a single query to ensure we get the correct values
        db.query('SELECT allowance, email FROM user WHERE id = ?', [userId], async (err, userResults) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            if (userResults.length > 0) {
                const { allowance, email } = userResults[0];

                // Check if the allowance is valid (should not be negative)
                if (allowance < 0) {
                    return res.status(400).json({ success: false, message: 'Allowance cannot be negative' });
                }

                // Send warning email
                try {
                    await sendWarningEmail(email, allowance);
                    return res.json({ success: true, allowance });
                } catch (emailError) {
                    console.error("Email error:", emailError);
                    return res.status(500).json({ success: false, message: 'Failed to send email' });
                }
            } else {
                return res.status(404).json({ success: false, message: 'User not found' });
            }
        });
    });
});


// Function to send warning email
async function sendWarningEmail(email, allowance) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, // Use environment variable
            pass: process.env.EMAIL_PASS, // Use environment variable
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Warning: Obscene Content Detected',
        text: `You have been warned for adding obscene and personal images.\n\n` +
              `Better be careful next time while adding the evidence.\n\n` +
              `Your allowance value is now ${allowance}. You have ${allowance} remaining warnings.\n` +
              `After this, you are not allowed to add evidence until a certain time.`
    };

    await transporter.sendMail(mailOptions);
}

//LOST AND FOUND 

// Route to serve Lost&Found lf_home.html if validated
app.get('/Lost&Found/lf_home.html', isAuthenticated, (req, res) => {
    const userId = req.session.userId;

    const sql = 'SELECT validate FROM user WHERE id = ?';
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Internal Server Error");
        }

        if (result.length > 0 && (result[0].validate === 1 || result[0].validate === true)) {
            res.sendFile(path.join(__dirname, 'public', 'User', 'Lost&Found', 'lf_home.html'));
        } else {
            res.status(403).send("Access denied: You are not validated.");
        }
    });
});


// Set up multer for file uploads
const storageAdmin = multer.diskStorage({
    destination: (req, file, cb) => {
        const itemFolderName = `${req.body.item_name}_${formatDate(new Date())}`;
        
        // Retrieve admin's folder path from the database using adminId
        const adminId = req.session.adminId; // Get admin ID from session (or any other source)
        
        // Query to get the admin's folder path from the database
        db.query('SELECT folder_path FROM admin WHERE id = ?', [adminId], (err, results) => {
            if (err) {
                return cb(err); // Return error if query fails
            }
            
            // Check if the admin exists and has a folder path
            if (results.length === 0 || !results[0].folder_path) {
                return cb(new Error('Admin folder not found.'));
            }

            const adminFolderPath = results[0].folder_path; // Get the admin's folder path
            const uploadPath = path.join(adminFolderPath,itemFolderName); // Full upload path

            // Create the directory if it doesn't exist
            fs.mkdirSync(uploadPath, { recursive: true });

            cb(null, uploadPath); // Callback with the upload path
        });
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}_${file.originalname}`);
    }
});

// Initialize the multer upload middleware
const adminUpload = multer({ storage: storageAdmin });
app.post('/admin/add-lost-item', adminUpload.fields([
    { name: 'media', maxCount: 5 },  // Accepting multiple media files (image/video)
    { name: 'pdf_upload', maxCount: 1 }  // Accepting one PDF file
]), (req, res) => {
    const adminId = req.session.adminId; // Get admin ID from session
    const { item_name, description, lost_date, station, police_complaint } = req.body;
    const createdAt = new Date(); // Current created date
    const itemFolderName = `${item_name}_${formatDate(createdAt)}`; 
    const l_id = `${item_name}_${formatToIST(createdAt)}`; // Item folder name based on item name and created date

    // Query to get the admin's folder path from the database
    db.query('SELECT folder_path FROM admin WHERE id = ?', [adminId], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }

        // Check if the admin exists and has a folder path
        if (results.length === 0 || !results[0].folder_path) {
            return res.status(404).json({ success: false, message: 'Admin folder not found.' });
        }

        const adminFolderPath = results[0].folder_path; // Get the admin's folder path
        const fullItemFolderPath = path.join(adminFolderPath, itemFolderName); // Full path for the item folder

        // Create the item folder if it doesn't exist
        fs.mkdirSync(fullItemFolderPath, { recursive: true });

        // Process the uploaded files (media and pdf)
        const files = req.files;
        if (files && (files.media || files.pdf_upload)) {
            const mediaPaths = (files.media || []).map((file, index) => {
                const newFileName = `${item_name}_${lost_date}_${index + 1}${path.extname(file.originalname)}`;
                const destinationPath = path.join(fullItemFolderPath, newFileName);

                // Move the media file to the item folder with the new name
                fs.renameSync(file.path, destinationPath);

                // Return the relative path for the file
                return path.join(itemFolderName, newFileName);
            });

            // Handle the PDF file (if uploaded)
            const pdfPath = files.pdf_upload ? path.join(fullItemFolderPath, `${item_name}_pdf${path.extname(files.pdf_upload[0].originalname)}`) : null;
            if (pdfPath) {
                fs.renameSync(files.pdf_upload[0].path, pdfPath);
            }
            

            // Insert the lost item record into the database
            const sql = `
                INSERT INTO lost_found (l_id,upld_id,item_name, description, lost_date, station, police_complaint, pdf_upload, media_paths, created_at, admin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            `;
            db.query(sql, [
                l_id,
                adminId,
                item_name, 
                description, 
                lost_date, 
                station, 
                police_complaint ? 1 : 0, // Convert boolean to integer (0 or 1)
                pdfPath,
                JSON.stringify(mediaPaths), // Store media paths as JSON string
                createdAt
            ], (err, result) => {
                if (err) {
                    console.error('Database insert error:', err);
                    return res.status(500).json({ success: false, message: err.message });
                }

                // Check if user details are provided and insert into user_item table
                const { user_name, user_email, user_phone, user_address } = req.body;

                if (user_name && user_email && user_phone && user_address) {
                    // First, check if the l_id (user_email or other identifier) already exists in the user_item table
                    const checkUserSql = 'SELECT * FROM user_item WHERE l_id = ?';
                    db.query(checkUserSql, [l_id], (err, userResults) => {
                        if (err) return res.status(500).json({ success: false, message: err.message });

                        // If user already exists, reject the request with an error
                        if (userResults.length > 0) {
                            return res.status(400).json({ success: false, message: 'User with this ID already exists in the user_item table.' });
                        }

                        // Insert the new user_item record
                        const sqlUserItem = `
                            INSERT INTO user_item (l_id, name, email, phone_number, address)
                            VALUES (?, ?, ?, ?, ?)
                        `;
                        db.query(sqlUserItem, [l_id, user_name, user_email, user_phone, user_address], (err, result) => {
                            if (err) return res.status(500).json({ success: false, message: err.message });

                            sendLostItemEmail(user_email, item_name, lost_date, l_id, createdAt, station, mediaPaths, pdfPath);
                            res.json({ success: true, message: 'Lost Item Uploaded Successfully!', redirectUrl: '/admin/dashboard.html' });
                        });
                    });
                } else {
                    res.json({ success: true, message: 'Lost item uploaded successfully without user details!', redirectUrl: '/admin/dashboard.html' });
                }
            });
        } else {
            return res.status(400).json({ success: false, message: 'No files were uploaded.' });
        }
    });
});


// Function to send the email
function sendLostItemEmail(userEmail, itemName, lostDate, l_id, createdAt, station, mediaPaths, pdfPath) {
    // Create a transporter
    const transporter = nodemailer.createTransport({
        service: 'gmail', // Or your SMTP provider
        auth: {
            user: process.env.EMAIL_USER, // Use environment variable
            pass: 'eacfkmfocqezrvpn',
        }
    });

    // Email template
    const emailTemplate = `
        <h1>Your Lost Product Report Has Been Successfully Registered</h1>
        <p>Dear User,</p>
        <p>We have successfully registered your lost item report. Here are the details:</p>
        <ul>
            <li><strong>Item Name:</strong> ${itemName}</li>
            <li><strong>Lost Date:</strong> ${lostDate}</li>
            <li><strong>Report ID (LID):</strong> ${l_id}</li>
            <li><strong>Created At:</strong> ${createdAt}</li>
            <li><strong>Police Station:</strong> ${station}</li>
        </ul>
        <p>Thank you for using our service.</p>
    `;

    // Mail options
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: userEmail,
        subject: 'Lost Item Report Successfully Registered',
        html: emailTemplate
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log("Sent");
        }
    });
}



app.get('/getPoliceRegistered', (req, res) => {
    const query = `
        SELECT lf.upld_id, lf.item_name, lf.description, lf.lost_date, lf.station, lf.media_paths, lf.created_at, a.folder_path 
        FROM lost_found lf
        JOIN admin a ON lf.upld_id = a.id
        WHERE lf.admin = 1
    `;

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }

        const itemsByUpldId = {};

        results.forEach(item => {
            if (!itemsByUpldId[item.upld_id]) {
                itemsByUpldId[item.upld_id] = {
                    upld_id: item.upld_id,
                    folder_path: item.folder_path,
                    items: []
                };
            }

            // Check if media_paths is already an array
            const mediaPaths = Array.isArray(item.media_paths)
                ? item.media_paths
                : JSON.parse(item.media_paths);

            // Combine folder path with each media path to get full paths
            const fullMediaPaths = mediaPaths.map(media => `${item.folder_path}/${media}`);

            itemsByUpldId[item.upld_id].items.push({
                item_name: item.item_name,
                description: item.description,
                lost_date: item.lost_date,
                station: item.station,
                created_at: item.created_at,
                media_paths: fullMediaPaths
            });
        });

        const responseData = Object.values(itemsByUpldId);
        res.json(responseData);
    });
});
// Set up Multer for temporary file upload
const tempStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'tempUploads/'); // Temporary folder for files before moving to final destination
    },
    filename: function (req, file, cb) {
        const extname = path.extname(file.originalname);
        cb(null, Date.now() + extname); // Use timestamp to avoid file name conflicts
    }
});

const up = multer({ storage: tempStorage });

app.post('/submitItemMedia', up.array('media', 5), (req, res) => {
    const { created_at, admin, description } = req.body;
    const user_id = req.session.userId;

    if (!created_at || !admin) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const datey = formatDateForDB(created_at);

    // Fetch l_id and upld_id based on the created_at and admin
    db.query('SELECT l_id, upld_id FROM lost_found WHERE created_at = ? AND admin = ?', [datey, admin], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: err.message });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'No matching record found' });
        }

        const { l_id, upld_id } = results[0];

        // Check if the combination of l_id and u_id exists in the communicate table
        db.query('SELECT * FROM communicate WHERE l_id = ? AND u_id = ?', [l_id, user_id], (err, existingRecord) => {
            if (err) {
                return res.status(500).json({ success: false, message: err.message });
            }

            // If the combination exists, return a message and do not proceed further
            if (existingRecord.length > 0) {
                req.files.forEach(file => {
                    fs.unlinkSync(file.path); // Remove each file in tempUploads folder
                });

                return res.status(200).json({
                    success: true,
                    message: 'Message has already been delivered for this item. Admin will communicate with you shortly.'
                });
            }

            // Proceed with the file upload and insertion into the communicate table
            db.query('SELECT folder_path FROM admin WHERE id = ?', [upld_id], (err, adminResults) => {
                if (err) {
                    return res.status(500).json({ success: false, message: err.message });
                }

                if (adminResults.length === 0 || !adminResults[0].folder_path) {
                    return res.status(404).json({ success: false, message: 'Admin folder not found.' });
                }

                const adminFolderPath = adminResults[0].folder_path;

                // Fetch file paths from the lost_found table using l_id
                db.query('SELECT media_paths FROM lost_found WHERE l_id = ?', [l_id], (err, lostFoundResults) => {
                    if (err) {
                        return res.status(500).json({ success: false, message: err.message });
                    }

                    if (lostFoundResults.length === 0) {
                        return res.status(404).json({ error: 'Lost found item not found' });
                    }

                    // Parse media paths
                    let filePaths;
                    try {
                        filePaths = Array.isArray(lostFoundResults[0].media_paths)
                            ? lostFoundResults[0].media_paths
                            : JSON.parse(lostFoundResults[0].media_paths);
                    } catch (error) {
                        return res.status(500).json({ error: 'Error parsing media paths' });
                    }

                    const partialPath = filePaths[0].split('/')[0]; // Extract folder name
                    const foundFolderPath = path.join(adminFolderPath, partialPath);

                    if (!fs.existsSync(foundFolderPath)) {
                        fs.mkdirSync(foundFolderPath, { recursive: true });
                    }

                    // Get row count from `communicate` to determine starting mediaCount
                    db.query('SELECT COUNT(*) AS count FROM communicate', (err, countResult) => {
                        if (err) {
                            return res.status(500).json({ success: false, message: err.message });
                        }

                        let mediaCount = countResult[0].count + 1;
                        const mediaPaths = [];

                        // Move files from tempUploads to the final directory
                        req.files.forEach(file => {
                            const newFileName = `found${mediaCount}${path.extname(file.originalname)}`;
                            const newFilePath = path.join(foundFolderPath, newFileName);

                            fs.renameSync(file.path, newFilePath); // Move file to final destination
                            mediaPaths.push(newFilePath);
                            mediaCount++; // Increment for each file
                        });

                        // Insert the new record into the communicate table
                        db.query(
                            'INSERT INTO communicate (l_id, u_id, file_path, description) VALUES (?, ?, ?, ?)',
                            [l_id, user_id, JSON.stringify(mediaPaths), description],
                            (err, insertResult) => {
                                if (err) {
                                    return res.status(500).json({ success: false, message: err.message });
                                }

                                // Update the communicate column in the lost_found table
                                db.query(
                                    'UPDATE lost_found SET communicate = communicate + 1 WHERE l_id = ? AND upld_id = ?',
                                    [l_id, upld_id],
                                    (err, updateResult) => {
                                        if (err) {
                                            return res.status(500).json({ success: false, message: err.message });
                                        }

                                        return res.status(200).json({
                                            success: true,
                                            message: 'Media and description submitted successfully.'
                                        });
                                    }
                                );
                            }
                        );
                    });
                });
            });
        });
    });
});



// Serve static files from the 'L&F' directory, which is outside the 'public' folder
app.use('/media', express.static(path.join(__dirname)));

// Route to get lost and found items with user details
app.get('/get_lost_found', (req, res) => {
    if (!req.session.adminId) {
        return res.redirect('/login'); // Redirect to login if no admin session exists
    }

    const adminId = req.session.adminId;
    const status = req.query.status;  // Get status query parameter
    let queryCondition;

    // Set query condition based on the status parameter
    if (status === 'investigated') {
        queryCondition = 'lf.informed > 0';
    } else if (status === 'uninvestigated') {
        queryCondition = 'lf.informed = 0';
    } else {
        return res.status(400).send('Invalid status parameter');
    }

    const query = `
        SELECT lf.l_id, lf.item_name, lf.lost_date, lf.description AS item_description,
               c.file_path, c.description AS user_description, u.name, u.phone_no, u.email
        FROM lost_found lf
        JOIN communicate c ON lf.l_id = c.l_id
        JOIN user u ON c.u_id = u.id
        WHERE lf.upld_id = ? AND ${queryCondition};
    `;

    db.query(query, [adminId], (err, results) => {
        if (err) {
            return res.status(500).send('Database error: ' + err.message);
        }

        const formattedResults = results.map(row => {
            let mediaPaths = [];
            if (Array.isArray(row.file_path)) {
                mediaPaths = row.file_path;
            } else if (typeof row.file_path === 'string') {
                try {
                    mediaPaths = JSON.parse(row.file_path);
                } catch (e) {
                    console.error('Error parsing file_path:', e);
                    mediaPaths = [];
                }
            }

            const fullMediaPaths = mediaPaths.map(media => `/media/${media}`);

            return {
                l_id: row.l_id,
                item_name: row.item_name,
                lost_date: formatDate(row.lost_date),
                description: row.item_description,
                media: fullMediaPaths,
                user: {
                    name: row.name,
                    phone_no: row.phone_no,
                    email: row.email,
                    description: row.user_description
                }
            };
        });
    

        res.json(formattedResults);
    });
});


app.use(express.json());

// Function to decode base64 string and get the mime type
function getMimeType(base64) {
    if (base64.startsWith('data:image')) {
        return 'image/jpeg'; // or png depending on the image format
    } else if (base64.startsWith('data:video')) {
        return 'video/mp4';
    } else {
        return 'application/octet-stream'; // Default type
    }
}
// Handle "Mark as Founded" button click for a specific item
app.post('/mark_as_founded', async (req, res) => {
    const { l_id, media, founder_name, founder_email } = req.body;
    console.log(founder_email, founder_name);

    // Fetch user email and item details based on l_id from the database
    const query = `
        SELECT u.email, lf.item_name
        FROM user_item u
        JOIN communicate c ON u.l_id = c.l_id
        JOIN lost_found lf ON lf.l_id = c.l_id
        WHERE lf.l_id = ?;
    `;
    
    db.query(query, [l_id], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error.' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found for given l_id.' });
        }

        const userEmail = results[0].email;
        const itemName = results[0].item_name;

        // Fetch police station details from admin table using the admin_id from the session
        const admin_id = req.session.adminId;  // Assuming admin_id is stored in the session
        const policeStationQuery = `
            SELECT police_station_name, address, pincode 
            FROM admin 
            WHERE id = ?;
        `;
        
        db.query(policeStationQuery, [admin_id], async (err, policeResults) => {
            if (err) {
                console.error('Error fetching police station details:', err);
                return res.status(500).json({ success: false, message: 'Error fetching police station details.' });
            }

            if (policeResults.length === 0) {
                return res.status(404).json({ success: false, message: 'Police station details not found.' });
            }

            const policeStationName = policeResults[0].police_station_name;
            const address = policeResults[0].address;
            const pincode = policeResults[0].pincode;

            // Set up Nodemailer transport
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL_USER, // Use environment variable
                    pass: process.env.EMAIL_PASS, // Use environment variable
                }
            });

            // Compose email for the user (item owner)
            const userMailOptions = {
                from: process.env.EMAIL_USER,
                to: userEmail,
                subject: 'Lost Item Found Notification',
                html: `<p>Dear User,</p>
                       <p>We are pleased to inform you that an item matching your lost item description, specifically "<strong>${itemName}</strong>", has been found. Please review the media attached below to confirm if this is indeed your lost item.</p>
                       <p>If you recognize the item, kindly reach out to us at your earliest convenience to arrange for its return. Our team is dedicated to ensuring the safe return of lost items and will assist you with the next steps in the process.</p>
                       <p>If you do recognize the item and would like to proceed with its return, we kindly request you to report the found item to the local police station for further verification. Below are the details of the police station where the item has been registered:</p>
                       <p><strong>Police Station Name:</strong> ${policeStationName}</p>
                       <p><strong>Address:</strong> ${address}</p>
                       <p><strong>Pincode:</strong> ${pincode}</p>
                       <p>If this is not your item, we apologize for the inconvenience and assure you that we continue to work diligently to reunite all lost items with their rightful owners.</p>
                       <p>Thank you for using Sadak Suvidha Service. We value your trust in us and are committed to providing the best possible service.</p>
                       <p>Should you have any questions or require further assistance, feel free to contact us at any time. We are here to help!</p>
                       <p>Best regards,</p>
                       <p>Tech Team</p>`,
                attachments: media.map((mediaBase64, index) => {
                    const mimeType = getMimeType(mediaBase64);
                    return {
                        filename: `media-${index + 1}.${mimeType.split('/')[1]}`,
                        content: mediaBase64.split("base64,")[1],
                        encoding: 'base64',
                        contentType: mimeType
                    };
                })
            };

            // Compose email for the founder
            const founderMailOptions = {
                from: process.env.EMAIL_USER,
                to: founder_email,
                subject: 'Thank You for Finding the Lost Item!',
                html: `<p>Dear ${founder_name},</p>
                       <p>Thank you for finding and submitting the lost item "<strong>${itemName}</strong>". Your valuable contribution has helped us bring this item one step closer to being returned to its rightful owner.</p>
                       <p>We kindly ask that you report the item to the local police station for further verification and processing. The police station details are as follows:</p>
                       <p><strong>Police Station Name:</strong> ${policeStationName}</p>
                       <p><strong>Address:</strong> ${address}</p>
                       <p><strong>Pincode:</strong> ${pincode}</p>
                       <p>Your help in this matter will not go unnoticed. By assisting in the return of this item, you may be eligible for a reward from both the police and the item's owner. Additionally, your valuable contribution will earn you points that can be redeemed for benefits from Sadak Suvidha.</p>
                       <p>We sincerely appreciate your cooperation and willingness to help others. Should you need any further assistance, feel free to reach out to us.</p>
                       <p>Best regards,</p>
                       <p>Sadak Suvidha Team</p>`
            };

            // Send email to the user (owner of the item)
            transporter.sendMail(userMailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email to user:', error);
                    return res.status(500).json({ success: false, message: 'Error sending email to user.' });
                }

                // Send email to the founder (the person who found the item)
                transporter.sendMail(founderMailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending email to founder:', error);
                        return res.status(500).json({ success: false, message: 'Error sending email to founder.' });
                    }

                    // Update the informed count for the lost item
                    db.query(
                        'UPDATE lost_found SET informed = informed + 1 WHERE l_id = ?',
                        [l_id],
                        (err, updateResult) => {
                            if (err) {
                                console.error('Error updating informed count:', err);
                                return res.status(500).json({ success: false, message: 'Error updating informed count.' });
                            }

                            res.json({ success: true, message: 'User and founder notified successfully. Informed count updated.' });
                        }
                    );
                });
                
            });
        });
    });
});



// Route to handle re-upload
app.post('/reupload_item', (req, res) => {
    const { l_id } = req.body;

    if (!l_id) {
        return res.status(400).json({ success: false, message: 'l_id is required' });
    }

    // Begin transaction to ensure data consistency
    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        // Update the 'informed' and 'communicate' fields in the lost_found table
        const updateLostFoundQuery = `
            UPDATE lost_found
            SET informed = 0, communicate = 0
            WHERE l_id = ?
        `;

        db.query(updateLostFoundQuery, [l_id], (updateErr, updateResult) => {
            if (updateErr) {
                console.error('Error updating lost_found:', updateErr);
                return db.rollback(() => res.status(500).json({ success: false, message: 'Database error' }));
            }

            // Delete the corresponding entries in the communicate table
            const deleteCommunicateQuery = `
                DELETE FROM communicate
                WHERE l_id = ?
            `;

            db.query(deleteCommunicateQuery, [l_id], (deleteErr, deleteResult) => {
                if (deleteErr) {
                    console.error('Error deleting from communicate:', deleteErr);
                    return db.rollback(() => res.status(500).json({ success: false, message: 'Database error' }));
                }

                // Commit the transaction
                db.commit(commitErr => {
                    if (commitErr) {
                        console.error('Error committing transaction:', commitErr);
                        return db.rollback(() => res.status(500).json({ success: false, message: 'Database error' }));
                    }

                    res.json({ success: true, message: 'Item re-uploaded successfully.' });
                });
            });
        });
    });
});

//view lost item for each card


app.post('/view_lost_item', async (req, res) => {
    const { l_id } = req.body;
    const adminId = req.session.adminId;
    // Ensure that both l_id and adminId are provided
    if (!l_id || !adminId) {
        return res.status(400).json({ success: false, message: 'Missing l_id or adminId' });
    }

    const query = `
        SELECT CONCAT(a.folder_path, '/', JSON_UNQUOTE(JSON_EXTRACT(l.media_paths, '$[0]'))) AS relative_path
        FROM lost_found l
        JOIN admin a ON l.upld_id = a.id
        WHERE l.l_id = ? AND a.id = ?
    `;

    db.query(query, [l_id, adminId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'Item not found' });
        }

        // Construct correct file paths
        const mediaPaths = results.map(row => {
            const relativePath = row.relative_path; // This is already `L&F/Admin/...`
            return path.join('/', relativePath); // Ensure leading slash but no extra `/public` prefix
        });
        

        res.json({ success: true, mediaPaths });
    });
});


  

// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
