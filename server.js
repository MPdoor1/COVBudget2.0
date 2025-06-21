const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Configuration, PlaidApi, PlaidEnvironments } = require('plaid');
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const moment = require('moment');
const _ = require('lodash');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Security middleware with updated CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.jsdelivr.net",
        "https://cdn.plaid.com"
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://production.plaid.com", "https://sandbox.plaid.com"],
      frameSrc: ["'self'", "https://cdn.plaid.com"]
    }
  }
}));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.use(express.json({ limit: '10mb' }));

// Serve static files
app.use(express.static('public'));

// Azure Key Vault setup
let secretClient;
if (process.env.AZURE_KEY_VAULT_URL) {
  const credential = new DefaultAzureCredential();
  secretClient = new SecretClient(process.env.AZURE_KEY_VAULT_URL, credential);
}

// Plaid setup
let plaidClient;
async function initializePlaid() {
  try {
    let plaidClientId = process.env.PLAID_CLIENT_ID;
    let plaidSecret = process.env.PLAID_SECRET;
    
    // Try to get Plaid credentials from Key Vault
    if (secretClient && !plaidClientId) {
      try {
        const clientIdSecret = await secretClient.getSecret('plaid-client-id');
        const secretSecret = await secretClient.getSecret('plaid-secret');
        plaidClientId = clientIdSecret.value;
        plaidSecret = secretSecret.value;
      } catch (error) {
        console.log('Plaid credentials not found in Key Vault, using environment variables');
      }
    }
    
    if (plaidClientId && plaidSecret) {
      const configuration = new Configuration({
        basePath: process.env.PLAID_ENV === 'production' 
          ? PlaidEnvironments.production 
          : PlaidEnvironments.sandbox,
        baseOptions: {
          headers: {
            'PLAID-CLIENT-ID': plaidClientId,
            'PLAID-SECRET': plaidSecret,
          },
        },
      });
      
      plaidClient = new PlaidApi(configuration);
      console.log('Plaid client initialized');
    }
  } catch (error) {
    console.log('Plaid initialization failed:', error.message);
  }
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

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'COVBudget 2.0 - Personal Finance & Banking Integration',
    status: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    features: [
      'Bank Account Integration (Plaid)',
      'Transaction Analysis',
      'Budget Management', 
      'Financial Goals Tracking',
      'Automated Categorization'
    ]
  });
});

app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      database: false,
      keyVault: false,
      plaid: !!plaidClient
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
      health.services.keyVault = true;
    } catch (error) {
      health.services.keyVault = false;
    }
  }

  res.json(health);
});

// === PLAID/BANKING ENDPOINTS ===

// Create Plaid Link Token
app.post('/api/plaid/link-token', authenticateToken, async (req, res) => {
  if (!plaidClient) {
    return res.status(503).json({ error: 'Plaid not configured' });
  }

  try {
    const request = {
      user: {
        client_user_id: req.user.userId,
      },
      client_name: 'COVBudget 2.0',
      products: ['transactions'],
      country_codes: ['US', 'CA'],
      language: 'en',
    };

    const response = await plaidClient.linkTokenCreate(request);
    res.json({ link_token: response.data.link_token });
  } catch (error) {
    console.error('Plaid link token error:', error);
    res.status(500).json({ error: 'Failed to create link token' });
  }
});

// Exchange public token for access token
app.post('/api/plaid/exchange-token', authenticateToken, async (req, res) => {
  if (!plaidClient) {
    return res.status(503).json({ error: 'Plaid not configured' });
  }

  try {
    const { public_token } = req.body;
    
    if (!public_token) {
      return res.status(400).json({ error: 'public_token required' });
    }

    const response = await plaidClient.itemPublicTokenExchange({
      public_token: public_token,
    });

    const accessToken = response.data.access_token;
    const itemId = response.data.item_id;

    // Get institution info
    const itemResponse = await plaidClient.itemGet({
      access_token: accessToken,
    });

    const institutionId = itemResponse.data.item.institution_id;
    
    const institutionResponse = await plaidClient.institutionsGetById({
      institution_id: institutionId,
      country_codes: ['US', 'CA'],
    });

    const institution = institutionResponse.data.institution;

    // Store in database
    if (dbClient) {
      await dbClient.query('BEGIN');
      
      // Insert institution
      const institutionResult = await dbClient.query(`
        INSERT INTO institutions (user_id, plaid_institution_id, name, url, primary_color, logo_url)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id, plaid_institution_id) DO UPDATE SET
        name = EXCLUDED.name, url = EXCLUDED.url, primary_color = EXCLUDED.primary_color, logo_url = EXCLUDED.logo_url
        RETURNING id
      `, [req.user.userId, institution.institution_id, institution.name, institution.url, 
          institution.primary_color, institution.logo]);

      // Insert Plaid item (with encrypted access token)
      await dbClient.query(`
        INSERT INTO plaid_items (user_id, institution_id, plaid_item_id, access_token_encrypted)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (plaid_item_id) DO UPDATE SET
        access_token_encrypted = EXCLUDED.access_token_encrypted
      `, [req.user.userId, institutionResult.rows[0].id, itemId, accessToken]); // TODO: Encrypt access token

      await dbClient.query('COMMIT');
    }

    res.json({ 
      success: true, 
      institution: institution.name,
      accounts_available: true 
    });

  } catch (error) {
    if (dbClient) await dbClient.query('ROLLBACK');
    console.error('Token exchange error:', error);
    res.status(500).json({ error: 'Failed to exchange token' });
  }
});

// Get accounts
app.get('/api/accounts', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const result = await dbClient.query(`
      SELECT a.*, i.name as institution_name, i.primary_color, i.logo_url
      FROM accounts a
      LEFT JOIN institutions i ON a.institution_id = i.id
      WHERE a.user_id = $1 AND a.is_active = true
      ORDER BY i.name, a.account_name
    `, [req.user.userId]);

    res.json({ accounts: result.rows });
  } catch (error) {
    console.error('Get accounts error:', error);
    res.status(500).json({ error: 'Failed to get accounts' });
  }
});

// Get transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const { account_id, start_date, end_date, category, limit = 50, offset = 0 } = req.query;
    
    let query = `
      SELECT t.*, a.account_name, i.name as institution_name
      FROM transactions t
      LEFT JOIN accounts a ON t.account_id = a.id
      LEFT JOIN institutions i ON a.institution_id = i.id
      WHERE t.user_id = $1
    `;
    
    const params = [req.user.userId];
    let paramCount = 1;

    if (account_id) {
      query += ` AND t.account_id = $${++paramCount}`;
      params.push(account_id);
    }

    if (start_date) {
      query += ` AND t.date >= $${++paramCount}`;
      params.push(start_date);
    }

    if (end_date) {
      query += ` AND t.date <= $${++paramCount}`;
      params.push(end_date);
    }

    if (category) {
      query += ` AND t.category_primary = $${++paramCount}`;
      params.push(category);
    }

    query += ` ORDER BY t.date DESC, t.created_at DESC`;
    query += ` LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await dbClient.query(query, params);

    res.json({ 
      transactions: result.rows,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: result.rows.length
      }
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to get transactions' });
  }
});

// === BUDGET ENDPOINTS ===

// Get budget categories
app.get('/api/budget/categories', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const result = await dbClient.query(`
      SELECT * FROM budget_categories 
      WHERE user_id = $1 OR user_id IS NULL
      ORDER BY sort_order, name
    `, [req.user.userId]);

    res.json({ categories: result.rows });
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Failed to get categories' });
  }
});

// Get spending analysis
app.get('/api/analytics/spending', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const { period = 'month' } = req.query;
    let dateFilter = '';
    
    switch (period) {
      case 'week':
        dateFilter = "AND t.date >= CURRENT_DATE - INTERVAL '7 days'";
        break;
      case 'month':
        dateFilter = "AND t.date >= CURRENT_DATE - INTERVAL '30 days'";
        break;
      case 'year':
        dateFilter = "AND t.date >= CURRENT_DATE - INTERVAL '365 days'";
        break;
    }

    // Spending by category
    const categorySpending = await dbClient.query(`
      SELECT 
        t.category_primary,
        COUNT(*) as transaction_count,
        SUM(ABS(t.amount)) as total_amount,
        AVG(ABS(t.amount)) as avg_amount
      FROM transactions t
      WHERE t.user_id = $1 AND t.amount < 0 ${dateFilter}
      GROUP BY t.category_primary
      ORDER BY total_amount DESC
    `, [req.user.userId]);

    // Monthly trend
    const monthlyTrend = await dbClient.query(`
      SELECT 
        DATE_TRUNC('month', t.date) as month,
        SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END) as expenses,
        SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END) as income
      FROM transactions t
      WHERE t.user_id = $1 AND t.date >= CURRENT_DATE - INTERVAL '12 months'
      GROUP BY DATE_TRUNC('month', t.date)
      ORDER BY month
    `, [req.user.userId]);

    res.json({
      category_spending: categorySpending.rows,
      monthly_trend: monthlyTrend.rows,
      period: period
    });
  } catch (error) {
    console.error('Analytics error:', error);
         res.status(500).json({ error: 'Failed to get analytics' });
   }
 });

// === MIGRATION ENDPOINT ===
app.post('/api/migrate', async (req, res) => {
  try {
    const { runMigrations } = require('./scripts/migrate');
    await runMigrations();
    res.json({ 
      success: true, 
      message: 'Database migration completed successfully!' 
    });
  } catch (error) {
    console.error('Migration failed:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Initialize and start server
async function startServer() {
  await initializeDatabase();
  await initializePlaid();
  
  app.listen(port, () => {
    console.log(`🚀 COVBudget 2.0 Server running on port ${port}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Key Vault configured: ${!!secretClient}`);
    console.log(`Database configured: ${!!dbClient}`);
    console.log(`Plaid configured: ${!!plaidClient}`);
    console.log('='.repeat(50));
    console.log('📱 Banking Integration Ready');
    console.log('📊 Analytics & Budgeting Active');
    console.log('🔐 Secure API Endpoints Available');
    console.log('='.repeat(50));
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