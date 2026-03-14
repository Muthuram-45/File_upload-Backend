const axios = require('axios');
require('dotenv').config();

(async () => {
    try {
        const portalUrl = 'http://localhost:4000';
        const bridgeKey = 'cloud-secret-bridge-2024';
        const email = 'manager@daveclarcloudsolutions.com';

        console.log(`Triggering sync for ${email}...`);
        const res = await axios.post(`${portalUrl}/api/sync-user-from-admin`, { email }, {
            headers: { 'x-api-key': bridgeKey }
        });
        console.log("Response:", res.data);
    } catch (err) {
        console.error("Sync Trigger Failed:", err.response ? err.response.data : err.message);
    }
})();
