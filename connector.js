// connector.js
require('dotenv').config();
const mysql = require('mysql2'); // Use mysql2

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    insecureAuth: true,
    // The following option might be necessary if you continue to have issues with authentication:
    // insecureAuth: true, // Uncomment this line if needed
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to the database');
});

module.exports = db;
