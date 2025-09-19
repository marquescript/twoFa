// Load .env.test for e2e tests
require('dotenv').config({ path: '.env.test' });

// Force NODE_ENV to development for tests
process.env.NODE_ENV = 'development';
