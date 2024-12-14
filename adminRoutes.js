// adminRoutes.js
const express = require('express');
const router = express.Router();
const db = require('./connector.js'); // Database connection

// Route to get evidence based on crime type
router.get('/evidence', (req, res) => {
    const crimeType = req.query.crimeType;

    const query = `
        SELECT u.name, u.email, up.location, up.description, up.upload_date, up.file_path, up.id AS evidence_id, up.verified
        FROM uploads up
        JOIN user u ON up.user_id = u.id
        WHERE up.evidence_type = ?
    `;

    db.query(query, [crimeType], (err, results) => {
        if (err) {
            console.error("Error fetching evidence data:", err);
            return res.status(500).json({ error: "Error fetching evidence data" });
        }
        res.json(results);
    });
});

// Route to verify evidence
router.post('/verifyEvidence/:id', (req, res) => {
    const evidenceId = req.params.id;

    const query = "UPDATE uploads SET verified = 1 WHERE id = ?";
    db.query(query, [evidenceId], (err, result) => {
        if (err) {
            console.error("Error verifying evidence:", err);
            return res.status(500).json({ error: "Error verifying evidence" });
        }
        res.sendStatus(200);
    });
});

module.exports = router;
