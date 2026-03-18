const mysql = require('mysql2/promise');
const fs = require('fs');

async function checkPortalUsers() {
    const connection = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: '8080',
        database: 'file_upload_db'
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
