const mysql = require('mysql2/promise');

const check = async () => {
    const db = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: '8080',
        database: 'file_upload_db'
    });
    const [rows] = await db.query("SELECT email, subscription_plan, subscription_expiry FROM users WHERE email LIKE '%muthu%'");
    console.log(JSON.stringify(rows, null, 2));
    await db.end();
};
check();
