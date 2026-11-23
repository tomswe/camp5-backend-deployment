const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:secret@localhost:5432/coffee_shop'
});

module.exports = pool;