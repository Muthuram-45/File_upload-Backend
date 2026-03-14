const mysql = require('mysql2/promise');

const fix = async () => {
    try {
        const db = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: '8080',
            database: 'file_upload_db'
        });
        
        const [result] = await db.query(
            "UPDATE users SET subscription_plan = '1year', subscription_expiry = '2027-03-12 18:30:00' WHERE email = 'muthuram921@gmail.com'"
        );
        
        console.log("Update Result:", result.affectedRows > 0 ? "SUCCESS" : "FAILED (Email not found)");
        
        const [rows] = await db.query("SELECT email, subscription_plan, subscription_expiry FROM users WHERE email = 'muthuram921@gmail.com'");
        console.log("Current User Status:", JSON.stringify(rows[0], null, 2));
        
        await db.end();
    } catch (err) {
        console.error("Error applying fix:", err.message);
    }
};
fix();
