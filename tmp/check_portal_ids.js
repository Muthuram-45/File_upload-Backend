const mysql = require('mysql2/promise');
const fs = require('fs');
require('dotenv').config();

async function checkPortalUsers() {
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'file_upload'
    });

    try {
        console.log('--- Checking Portal Users ---');
        const [rows] = await connection.execute('SELECT id, first_name, last_name, email FROM users WHERE email IN ("manager@daveclarcloudsolutions.com", "jeeva@daveclarcloudsolutions.com")');
        fs.writeFileSync('tmp/portal_id_check.json', JSON.stringify(rows, null, 2));
        console.log('✅ Results written to tmp/portal_id_check.json');
    } catch (error) {
        console.error('❌ Error:', error.message);
    } finally {
        await connection.end();
    }
}

checkPortalUsers();
