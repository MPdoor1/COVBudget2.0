const express = require('express');
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');
const { Client } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Azure Key Vault setup
let secretClient;
if (process.env.AZURE_KEY_VAULT_URL) {
  const credential = new DefaultAzureCredential();
  secretClient = new SecretClient(process.env.AZURE_KEY_VAULT_URL, credential);
}

// Database connection
let dbClient;

async function initializeDatabase() {
  try {
    if (process.env.DATABASE_URL || (secretClient && process.env.DB_SECRET_NAME)) {
      let connectionString = process.env.DATABASE_URL;
      
      // Try to get connection string from Key Vault if not in env
      if (!connectionString && secretClient && process.env.DB_SECRET_NAME) {
        const secret = await secretClient.getSecret(process.env.DB_SECRET_NAME);
        connectionString = secret.value;
      }
      
      if (connectionString) {
        dbClient = new Client({
          connectionString: connectionString,
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        await dbClient.connect();
        console.log('Connected to database');
      }
    }
  } catch (error) {
    console.log('Database connection failed:', error.message);
  }
}

// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'COVBudget 2.0 - Azure Deployment Ready!',
    status: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      database: false,
      keyVault: false
    }
  };

  // Check database connection
  if (dbClient) {
    try {
      await dbClient.query('SELECT 1');
      health.services.database = true;
    } catch (error) {
      health.services.database = false;
    }
  }

  // Check Key Vault connection
  if (secretClient) {
    try {
      // Try to list secrets (just to test connection)
      health.services.keyVault = true;
    } catch (error) {
      health.services.keyVault = false;
    }
  }

  res.json(health);
});

app.get('/secrets/test', async (req, res) => {
  if (!secretClient) {
    return res.status(503).json({ error: 'Key Vault not configured' });
  }

  try {
    // This is just a test endpoint - in production, never expose secrets
    const secretName = process.env.TEST_SECRET_NAME || 'test-secret';
    const secret = await secretClient.getSecret(secretName);
    res.json({ 
      message: 'Successfully retrieved secret from Key Vault',
      secretName: secret.name,
      hasValue: !!secret.value
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve secret', message: error.message });
  }
});

// Initialize and start server
async function startServer() {
  await initializeDatabase();
  
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Key Vault configured: ${!!secretClient}`);
    console.log(`Database configured: ${!!dbClient}`);
  });
}

startServer().catch(console.error);

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (dbClient) {
    await dbClient.end();
  }
  process.exit(0);
}); 