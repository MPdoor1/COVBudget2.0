const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const csv = require('csv-parser');
const xlsx = require('xlsx');
const fs = require('fs');
const path = require('path');
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

// Security middleware with properly configured CSP
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
      scriptSrcElem: [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://cdn.plaid.com"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      styleSrcElem: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      styleSrcAttr: ["'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://production.plaid.com", "https://sandbox.plaid.com"],
      frameSrc: ["'self'", "https://cdn.plaid.com"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
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

// In-memory storage for development
let mockUsers = [];
let mockAccounts = [];
let mockTransactions = [];
let mockBudgetCategories = [];

// Database query helper function
const query = async (text, params) => {
  if (!dbClient) {
    if (process.env.NODE_ENV === 'development') {
      // Mock database for development
      return await mockQuery(text, params);
    } else {
      throw new Error('Database not connected');
    }
  }
  return await dbClient.query(text, params);
};

// Mock query function for development
const mockQuery = async (text, params) => {
  console.log('Mock query:', text, params);
  
  // Handle INSERT INTO accounts
  if (text.includes('INSERT INTO accounts')) {
    const [userId, name, type, bankName, balance] = params;
    const newAccount = {
      id: 'mock-' + Date.now(),
      user_id: userId,
      name,
      type,
      bank_name: bankName,
      balance: balance || 0,
      is_active: true,
      created_at: new Date(),
      updated_at: new Date()
    };
    mockAccounts.push(newAccount);
    return { rows: [newAccount] };
  }
  
  // Handle SELECT from accounts
  if (text.includes('SELECT') && text.includes('accounts')) {
    const userAccounts = mockAccounts.filter(acc => acc.user_id === params[0] && acc.is_active);
    return { rows: userAccounts };
  }
  
  // Handle SELECT from transactions
  if (text.includes('SELECT') && text.includes('transactions')) {
    const userTransactions = mockTransactions.filter(tx => tx.user_id === params[0]);
    return { rows: userTransactions };
  }
  
  // Handle SELECT from budget_categories
  if (text.includes('SELECT') && text.includes('budget_categories')) {
    const userCategories = mockBudgetCategories.filter(cat => cat.user_id === params[0]);
    return { rows: userCategories };
  }
  
  // Handle INSERT INTO budget_categories
  if (text.includes('INSERT INTO budget_categories')) {
    const [userId, name, budgetedAmount] = params;
    const newCategory = {
      id: 'mock-cat-' + Date.now(),
      user_id: userId,
      name,
      budgeted_amount: budgetedAmount,
      created_at: new Date(),
      updated_at: new Date()
    };
    mockBudgetCategories.push(newCategory);
    return { rows: [newCategory] };
  }
  
  // Handle INSERT INTO users (registration)
  if (text.includes('INSERT INTO users')) {
    const [name, email, passwordHash] = params;
    const newUser = {
      id: 'mock-user-' + Date.now(),
      name,
      email,
      password_hash: passwordHash,
      created_at: new Date(),
      updated_at: new Date()
    };
    mockUsers.push(newUser);
    return { rows: [newUser] };
  }
  
  // Handle SELECT from users (login)
  if (text.includes('SELECT') && text.includes('users') && text.includes('email')) {
    const email = params[0];
    const user = mockUsers.find(u => u.email === email);
    return { rows: user ? [user] : [] };
  }
  
  // Default empty response
  return { rows: [] };
};

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
    // In development mode, allow a mock user for testing
    if (process.env.NODE_ENV === 'development' && token === 'mock-token') {
      req.user = { userId: 'mock-user-123', email: 'test@example.com' };
      return next();
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api', (req, res) => {
  res.json({
    message: 'COVBudget 2.0 - Council Financial Management',
    status: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    features: [
      'Multi-Account Management',
      'Bank Statement Upload',
      'Transaction Analysis',
      'Budget Management', 
      'Financial Analytics',
      'Council Oversight Tools'
    ]
  });
});

// Health check endpoint (no auth required)
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

// API Health check endpoint (for frontend)
app.get('/api/health', async (req, res) => {
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
      console.error('Database health check failed:', error);
      health.services.database = false;
    }
  }

  // Check Key Vault connection
  if (secretClient) {
    try {
      health.services.keyVault = true;
    } catch (error) {
      console.error('Key Vault health check failed:', error);
      health.services.keyVault = false;
    }
  }

  res.json(health);
});

// Database diagnostic endpoint
app.get('/api/db-test', async (req, res) => {
  console.log('=== DATABASE DIAGNOSTIC TEST ===');
  console.log('Environment:', process.env.NODE_ENV);
  console.log('Database client exists:', !!dbClient);
  
  try {
    if (!dbClient) {
      console.log('ERROR: No database client available');
      return res.json({
        success: false,
        error: 'No database client',
        details: {
          environment: process.env.NODE_ENV,
          dbClient: !!dbClient,
          connectionString: process.env.DATABASE_URL ? 'SET' : 'NOT SET'
        }
      });
    }
    
    console.log('Testing basic database query...');
    const result = await query('SELECT NOW() as current_time, current_database() as db_name');
    console.log('Database query result:', result);
    
    console.log('Testing accounts table...');
    const tableTest = await query('SELECT COUNT(*) as count FROM accounts');
    console.log('Accounts table test:', tableTest);
    
    console.log('Testing users table...');
    const usersTest = await query('SELECT COUNT(*) as count FROM users');
    console.log('Users table test:', usersTest);
    
    res.json({
      success: true,
      message: 'Database connection working',
      database_info: result.rows[0],
      accounts_count: tableTest.rows[0].count,
      users_count: usersTest.rows[0].count,
      details: {
        environment: process.env.NODE_ENV,
        dbClient: !!dbClient,
        connectionString: process.env.DATABASE_URL ? 'SET' : 'NOT SET'
      }
    });
    
  } catch (error) {
    console.error('Database test error:', error);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      details: {
        environment: process.env.NODE_ENV,
        dbClient: !!dbClient,
        connectionString: process.env.DATABASE_URL ? 'SET' : 'NOT SET'
      }
    });
  }
});

// Test account creation without auth (REMOVE AFTER DEBUGGING)
app.post('/api/test-account', async (req, res) => {
  try {
    console.log('=== TEST ACCOUNT CREATION (NO AUTH) ===');
    console.log('Request body:', req.body);
    
    const { name, type, bank_name, balance, user_id } = req.body;
    
    if (!name || !type || !bank_name || !user_id) {
      return res.status(400).json({ error: 'Missing required fields: name, type, bank_name, user_id' });
    }
    
    console.log('Testing database query...');
    const queryText = `
      INSERT INTO accounts (user_id, name, type, bank_name, balance, is_active)
      VALUES ($1, $2, $3, $4, $5, true)
      RETURNING *
    `;
    const queryParams = [user_id, name, type, bank_name, balance || 0];
    console.log('Query:', queryText);
    console.log('Params:', queryParams);
    
    const result = await query(queryText, queryParams);
    console.log('SUCCESS! Account created:', result.rows[0]);
    
    res.json({
      success: true,
      account: result.rows[0]
    });
    
  } catch (error) {
    console.error('Test account creation error:', error);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    res.status(500).json({
      success: false,
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
      return res.status(503).json({ error: 'Database not available' });
    }

    const result = await query(`
      SELECT a.*, i.name as institution_name, i.primary_color, i.logo_url
      FROM accounts a
      LEFT JOIN institutions i ON a.institution_id = i.id
      WHERE a.user_id = $1 AND a.is_active = true
      ORDER BY COALESCE(i.name, a.bank_name), a.name
    `, [req.user.userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get accounts error:', error);
    res.status(500).json({ error: 'Failed to get accounts' });
  }
});

// Create new account
app.post('/api/accounts', authenticateToken, async (req, res) => {
  try {
    console.log('=== ACCOUNT CREATION DEBUG ===');
    console.log('Environment:', process.env.NODE_ENV);
    console.log('Database client exists:', !!dbClient);
    console.log('Request body:', req.body);
    console.log('User info:', req.user);
    
    if (!dbClient && process.env.NODE_ENV !== 'development') {
      console.log('ERROR: Database not available in production');
      return res.status(503).json({ error: 'Database not available' });
    }
    
    const { name, type, bank_name, balance } = req.body;
    console.log('Extracted fields:', { name, type, bank_name, balance });
    
    if (!name || !type || !bank_name) {
      console.log('ERROR: Missing required fields');
      return res.status(400).json({ error: 'Name, type, and bank name are required' });
    }
    
    console.log('About to execute database query...');
    const queryText = `
      INSERT INTO accounts (user_id, name, type, bank_name, balance, is_active)
      VALUES ($1, $2, $3, $4, $5, true)
      RETURNING *
    `;
    const queryParams = [req.user.userId, name, type, bank_name, balance || 0];
    console.log('Query:', queryText);
    console.log('Params:', queryParams);
    
    const result = await query(queryText, queryParams);
    console.log('Query result:', result);
    console.log('Returned account:', result.rows[0]);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating account:', error);
    console.error('Error stack:', error.stack);
    console.error('Error message:', error.message);
    console.error('Database client status:', !!dbClient);
    console.error('Request body:', req.body);
    console.error('User info:', req.user);
    
    res.status(500).json({ 
      error: 'Failed to create account',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Update account
app.put('/api/accounts/:id', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }
    
    const { id } = req.params;
    const { name, type, bank_name, balance } = req.body;
    
    const result = await query(`
      UPDATE accounts 
      SET name = $1, type = $2, bank_name = $3, balance = $4, updated_at = CURRENT_TIMESTAMP
      WHERE id = $5 AND user_id = $6 AND is_active = true
      RETURNING *
    `, [name, type, bank_name, balance, id, req.user.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating account:', error);
    res.status(500).json({ error: 'Failed to update account' });
  }
});

// Delete account (soft delete)
app.delete('/api/accounts/:id', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }
    
    const { id } = req.params;
    
    const result = await query(`
      UPDATE accounts 
      SET is_active = false, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1 AND user_id = $2
      RETURNING *
    `, [id, req.user.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Get transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const { account_id, start_date, end_date, category, limit = 50, offset = 0 } = req.query;
    
    let queryText = `
      SELECT t.*, 
             COALESCE(a.name, a.account_name) as account_name, 
             COALESCE(i.name, a.bank_name) as institution_name,
             COALESCE(t.category_primary, t.category) as category
      FROM transactions t
      LEFT JOIN accounts a ON t.account_id = a.id
      LEFT JOIN institutions i ON a.institution_id = i.id
      WHERE t.user_id = $1
    `;
    
    const params = [req.user.userId];
    let paramCount = 1;

    if (account_id) {
      queryText += ` AND t.account_id = $${++paramCount}`;
      params.push(account_id);
    }

    if (start_date) {
      queryText += ` AND t.date >= $${++paramCount}`;
      params.push(start_date);
    }

    if (end_date) {
      queryText += ` AND t.date <= $${++paramCount}`;
      params.push(end_date);
    }

    if (category) {
      queryText += ` AND (t.category_primary = $${++paramCount} OR t.category = $${paramCount})`;
      params.push(category);
    }

    queryText += ` ORDER BY t.date DESC, t.created_at DESC`;
    queryText += ` LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await query(queryText, params);

    res.json(result.rows);
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to get transactions' });
  }
});

// Update transaction
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const { id } = req.params;
    const { category, description, amount } = req.body;

    let updateFields = [];
    let params = [req.user.userId, id];
    let paramCount = 2;

    if (category !== undefined) {
      updateFields.push(`category_primary = $${++paramCount}, category = $${paramCount}`);
      params.push(category);
    }

    if (description !== undefined) {
      updateFields.push(`description = $${++paramCount}`);
      params.push(description);
    }

    if (amount !== undefined) {
      updateFields.push(`amount = $${++paramCount}`);
      params.push(amount);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const queryText = `
      UPDATE transactions 
      SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $1 AND id = $2
      RETURNING *
    `;

    const result = await query(queryText, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update transaction error:', error);
    res.status(500).json({ error: 'Failed to update transaction' });
  }
});

// === BUDGET ENDPOINTS ===

// Get budget categories
app.get('/api/budget/categories', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const result = await query(`
      SELECT * FROM budget_categories 
      WHERE user_id = $1 OR user_id IS NULL
      ORDER BY sort_order, name
    `, [req.user.userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Failed to get categories' });
  }
});

// Alternative endpoint for dashboard compatibility
app.get('/api/budget-categories', authenticateToken, async (req, res) => {
  try {
    if (!dbClient && process.env.NODE_ENV !== 'development') {
      return res.status(503).json({ error: 'Database not available' });
    }

    const result = await query(`
      SELECT bc.*, 
             COALESCE(spent.amount, 0) as spent_amount
      FROM budget_categories bc
      LEFT JOIN (
        SELECT category_primary, SUM(ABS(amount)) as amount
        FROM transactions 
        WHERE user_id = $1 AND amount < 0 
        AND date >= DATE_TRUNC('month', CURRENT_DATE)
        GROUP BY category_primary
      ) spent ON bc.name = spent.category_primary
      WHERE bc.user_id = $1 OR bc.user_id IS NULL
      ORDER BY bc.sort_order, bc.name
    `, [req.user.userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get budget categories error:', error);
    res.status(500).json({ error: 'Failed to get budget categories' });
  }
});

// Create budget category
app.post('/api/budget-categories', authenticateToken, async (req, res) => {
  try {
    if (!dbClient && process.env.NODE_ENV !== 'development') {
      return res.status(503).json({ error: 'Database not available' });
    }

    const { name, budgeted_amount, sort_order = 999 } = req.body;
    
    if (!name || !budgeted_amount) {
      return res.status(400).json({ error: 'Name and budgeted amount are required' });
    }

    const result = await query(`
      INSERT INTO budget_categories (user_id, name, budgeted_amount, sort_order)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `, [req.user.userId, name, budgeted_amount, sort_order]);

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create budget category error:', error);
    res.status(500).json({ error: 'Failed to create budget category' });
  }
});

// Update budget category
app.put('/api/budget-categories/:id', authenticateToken, async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const { id } = req.params;
    const { name, budgeted_amount, sort_order } = req.body;

    const result = await query(`
      UPDATE budget_categories 
      SET name = $1, budgeted_amount = $2, sort_order = $3, updated_at = CURRENT_TIMESTAMP
      WHERE id = $4 AND user_id = $5
      RETURNING *
    `, [name, budgeted_amount, sort_order, id, req.user.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Budget category not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update budget category error:', error);
    res.status(500).json({ error: 'Failed to update budget category' });
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

// === FILE UPLOAD CONFIGURATION ===
const upload = multer({
  dest: 'uploads/',
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.csv', '.xlsx', '.xls'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only CSV and Excel files are allowed'), false);
    }
  }
});

// Bank statement upload endpoint (requires authentication)
app.post('/api/upload-statement', authenticateToken, upload.single('statement'), async (req, res) => {
  try {
    if (!dbClient) {
      return res.status(503).json({ error: 'Database not available' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { account_id, accountName = 'Unknown Account' } = req.body;
    
    // Verify account ownership if account_id is provided
    if (account_id) {
      const accountCheck = await query(
        'SELECT id FROM accounts WHERE id = $1 AND user_id = $2 AND is_active = true',
        [account_id, req.user.userId]
      );
      
      if (accountCheck.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid account or account not found' });
      }
    }

    const filePath = req.file.path;
    const fileName = req.file.originalname;
    const fileExt = path.extname(fileName).toLowerCase();

    console.log(`Processing statement upload: ${fileName}`);

    let transactions = [];

    try {
      if (fileExt === '.csv') {
        // Parse CSV file
        transactions = await parseCSVFile(filePath);
      } else if (fileExt === '.xlsx' || fileExt === '.xls') {
        // Parse Excel file
        transactions = await parseExcelFile(filePath);
      }

      if (transactions.length === 0) {
        throw new Error('No valid transactions found in file');
      }

      // Create or get institution and account
      const institutionResult = await dbClient.query(`
        INSERT INTO institutions (name, country) 
        VALUES ($1, 'US') 
        ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
        RETURNING id
      `, [accountName]);

      // Use provided account_id or create new account
      let accountId;
      
      if (account_id) {
        accountId = account_id;
      } else {
        // Create new account for this upload
        const accountResult = await query(`
          INSERT INTO accounts (user_id, name, type, bank_name, is_active)
          VALUES ($1, $2, 'checking', 'Uploaded Bank', true)
          RETURNING id
        `, [req.user.userId, accountName]);
        
        accountId = accountResult.rows[0].id;
      }

      // Insert transactions
      let insertedCount = 0;
      for (const transaction of transactions) {
        try {
          await query(`
            INSERT INTO transactions (
              user_id, account_id, transaction_id, amount, date, description, 
              category_primary, category, merchant_name, 
              iso_currency_code, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (account_id, transaction_id) DO NOTHING
          `, [
            req.user.userId,
            accountId,
            `upload_${Date.now()}_${insertedCount}`, // Unique transaction ID
            transaction.amount,
            transaction.date,
            transaction.description,
            transaction.category || 'Other',
            transaction.category || 'Other',
            transaction.merchant || null,
            'USD'
          ]);
          insertedCount++;
        } catch (txError) {
          console.warn(`Failed to insert transaction: ${txError.message}`);
        }
      }

      // Get date range for summary
      const dates = transactions.map(t => t.date).sort();
      const dateRange = dates.length > 0 ? 
        `${dates[0]} to ${dates[dates.length - 1]}` : 'Unknown';

      res.json({
        success: true,
        transactions_count: insertedCount,
        transactionCount: insertedCount,
        totalParsed: transactions.length,
        accountName: accountName,
        dateRange: dateRange,
        message: `Successfully processed ${insertedCount} transactions`
      });

    } catch (parseError) {
      console.error('File parsing error:', parseError);
      res.status(400).json({ 
        error: `Failed to parse file: ${parseError.message}` 
      });
    } finally {
      // Clean up uploaded file
      try {
        fs.unlinkSync(filePath);
      } catch (cleanupError) {
        console.warn('Failed to cleanup uploaded file:', cleanupError.message);
      }
    }

  } catch (error) {
    console.error('Statement upload error:', error);
    res.status(500).json({ error: 'Failed to process statement upload' });
  }
});

// Helper function to parse CSV files
function parseCSVFile(filePath) {
  return new Promise((resolve, reject) => {
    const transactions = [];
    
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (row) => {
        try {
          const transaction = parseTransactionRow(row);
          if (transaction) {
            transactions.push(transaction);
          }
        } catch (error) {
          console.warn('Failed to parse row:', error.message);
        }
      })
      .on('end', () => {
        resolve(transactions);
      })
      .on('error', reject);
  });
}

// Helper function to parse Excel files
function parseExcelFile(filePath) {
  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const jsonData = xlsx.utils.sheet_to_json(worksheet);
    
    const transactions = [];
    for (const row of jsonData) {
      try {
        const transaction = parseTransactionRow(row);
        if (transaction) {
          transactions.push(transaction);
        }
      } catch (error) {
        console.warn('Failed to parse row:', error.message);
      }
    }
    
    return transactions;
  } catch (error) {
    throw new Error(`Failed to parse Excel file: ${error.message}`);
  }
}

// Helper function to parse individual transaction rows
function parseTransactionRow(row) {
  // Try to find date column (various possible names)
  const dateFields = ['date', 'Date', 'DATE', 'Transaction Date', 'Posted Date', 'posting_date'];
  const descFields = ['description', 'Description', 'DESCRIPTION', 'Memo', 'memo', 'Transaction Description'];
  const amountFields = ['amount', 'Amount', 'AMOUNT', 'Debit', 'Credit', 'Transaction Amount'];

  let date = null;
  let description = null;
  let amount = null;

  // Find date
  for (const field of dateFields) {
    if (row[field]) {
      date = parseDate(row[field]);
      break;
    }
  }

  // Find description
  for (const field of descFields) {
    if (row[field]) {
      description = String(row[field]).trim();
      break;
    }
  }

  // Find amount
  for (const field of amountFields) {
    if (row[field] !== undefined && row[field] !== '') {
      amount = parseFloat(String(row[field]).replace(/[,$]/g, ''));
      break;
    }
  }

  // Handle separate debit/credit columns
  if (amount === null) {
    const debit = parseFloat(String(row['Debit'] || row['debit'] || '0').replace(/[,$]/g, ''));
    const credit = parseFloat(String(row['Credit'] || row['credit'] || '0').replace(/[,$]/g, ''));
    
    if (!isNaN(debit) && debit !== 0) {
      amount = -Math.abs(debit); // Debits are negative
    } else if (!isNaN(credit) && credit !== 0) {
      amount = Math.abs(credit); // Credits are positive
    }
  }

  if (!date || !description || amount === null || isNaN(amount)) {
    return null; // Skip invalid rows
  }

  // Auto-categorize based on description
  const category = categorizeTransaction(description);

  return {
    date: date,
    description: description,
    amount: amount,
    category: category,
    merchant: extractMerchant(description)
  };
}

// Helper function to parse dates
function parseDate(dateStr) {
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) {
    // Try parsing MM/DD/YYYY format
    const parts = String(dateStr).split(/[\/\-]/);
    if (parts.length === 3) {
      const month = parseInt(parts[0]) - 1;
      const day = parseInt(parts[1]);
      const year = parseInt(parts[2]);
      return new Date(year, month, day).toISOString().split('T')[0];
    }
    throw new Error(`Invalid date format: ${dateStr}`);
  }
  return date.toISOString().split('T')[0];
}

// Simple transaction categorization
function categorizeTransaction(description) {
  const desc = description.toLowerCase();
  
  if (desc.includes('grocery') || desc.includes('food') || desc.includes('restaurant') || desc.includes('cafe')) {
    return 'Food & Dining';
  } else if (desc.includes('gas') || desc.includes('fuel') || desc.includes('uber') || desc.includes('taxi')) {
    return 'Transportation';
  } else if (desc.includes('amazon') || desc.includes('walmart') || desc.includes('target') || desc.includes('shopping')) {
    return 'Shopping';
  } else if (desc.includes('electric') || desc.includes('water') || desc.includes('internet') || desc.includes('phone')) {
    return 'Bills & Utilities';
  } else if (desc.includes('salary') || desc.includes('payroll') || desc.includes('deposit') || desc.includes('income')) {
    return 'Income';
  } else if (desc.includes('movie') || desc.includes('netflix') || desc.includes('spotify') || desc.includes('entertainment')) {
    return 'Entertainment';
  } else if (desc.includes('hospital') || desc.includes('doctor') || desc.includes('pharmacy') || desc.includes('medical')) {
    return 'Healthcare';
  } else {
    return 'Other';
  }
}

// Extract merchant name from description
function extractMerchant(description) {
  // Simple merchant extraction - take first part before common separators
  const cleaned = description.replace(/[0-9\-#*]/g, '').trim();
  const parts = cleaned.split(/\s+/);
  return parts.slice(0, 2).join(' '); // Take first two words
}

// === AUTHENTICATION ENDPOINTS ===
app.post('/api/auth/register', async (req, res) => {
  try {
    // Check if database is available
    if (!dbClient) {
      return res.status(503).json({ 
        error: 'Database service unavailable. Please run migrations first.',
        needsMigration: true 
      });
    }

    // Test database connection
    try {
      await query('SELECT 1');
    } catch (connectionError) {
      console.error('Database connection test failed:', connectionError);
      return res.status(503).json({ 
        error: 'Database connection failed. Please check your database configuration.',
        needsMigration: true 
      });
    }

    const { name, email, password } = req.body;
    
    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    // Check if users table exists, if not suggest running migrations
    try {
      const existingUser = await query('SELECT id FROM users WHERE email = $1', [email]);
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'User already exists with this email' });
      }
    } catch (dbError) {
      if (dbError.code === '42P01') { // Table doesn't exist
        return res.status(503).json({ 
          error: 'Database tables not initialized. Please run migrations first.',
          needsMigration: true 
        });
      }
      throw dbError;
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const result = await query(
      'INSERT INTO users (name, email, password_hash, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email, created_at',
      [name, email, hashedPassword]
    );
    
    const user = result.rows[0];
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.created_at
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Registration failed', 
      details: error.message,
      code: error.code
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    // Check if database is available
    if (!dbClient) {
      return res.status(503).json({ error: 'Database service unavailable. Please run migrations first.' });
    }

    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user
    let result;
    try {
      result = await query('SELECT * FROM users WHERE email = $1', [email]);
    } catch (dbError) {
      if (dbError.code === '42P01') { // Table doesn't exist
        return res.status(503).json({ 
          error: 'Database tables not initialized. Please run migrations first.',
          needsMigration: true 
        });
      }
      throw dbError;
    }

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Update last login
    try {
      await query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    } catch (updateError) {
      console.warn('Failed to update last login:', updateError);
      // Don't fail login for this
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.created_at,
        lastLogin: new Date()
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Login failed', 
      details: process.env.NODE_ENV === 'development' ? error.message : undefined 
    });
  }
});



// === USER DATA ENDPOINTS ===
app.get('/api/user/transactions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { limit = 50, offset = 0 } = req.query;
    
    const result = await query(`
      SELECT t.*, a.account_name, i.name as institution_name
      FROM transactions t
      JOIN accounts a ON t.account_id = a.id
      JOIN institutions i ON a.institution_id = i.id
      WHERE a.user_id = $1
      ORDER BY t.date DESC
      LIMIT $2 OFFSET $3
    `, [userId, limit, offset]);
    
    res.json({
      success: true,
      transactions: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error('Error fetching user transactions:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/user/accounts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const result = await query(`
      SELECT a.*, i.name as institution_name,
             COUNT(t.id) as transaction_count,
             COALESCE(SUM(t.amount), 0) as balance
      FROM accounts a
      JOIN institutions i ON a.institution_id = i.id
      LEFT JOIN transactions t ON a.id = t.account_id
      WHERE a.user_id = $1
      GROUP BY a.id, i.name
      ORDER BY a.created_at DESC
    `, [userId]);
    
    res.json({
      success: true,
      accounts: result.rows
    });
  } catch (error) {
    console.error('Error fetching user accounts:', error);
    res.status(500).json({ error: 'Failed to fetch accounts' });
  }
});

app.get('/api/user/spending-summary', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { months = 3 } = req.query;
    
    const result = await query(`
      SELECT 
        t.category_primary,
        COUNT(*) as transaction_count,
        SUM(CASE WHEN t.amount < 0 THEN ABS(t.amount) ELSE 0 END) as total_spent,
        SUM(CASE WHEN t.amount > 0 THEN t.amount ELSE 0 END) as total_income
      FROM transactions t
      JOIN accounts a ON t.account_id = a.id
      WHERE a.user_id = $1 
        AND t.date >= NOW() - INTERVAL '${months} months'
      GROUP BY t.category_primary
      ORDER BY total_spent DESC
    `, [userId]);
    
    res.json({
      success: true,
      summary: result.rows,
      period: `${months} months`
    });
  } catch (error) {
    console.error('Error fetching spending summary:', error);
    res.status(500).json({ error: 'Failed to fetch spending summary' });
  }
});

// === MIGRATION ENDPOINT ===
app.post('/api/migrate', async (req, res) => {
  try {
    console.log('Starting database migration...');
    
    // Check if migration script exists
    const path = require('path');
    const migrationPath = path.join(__dirname, 'scripts', 'migrate.js');
    console.log('Migration script path:', migrationPath);
    
    const { runMigrations } = require('./scripts/migrate');
    await runMigrations();
    console.log('Database migration completed successfully!');
    
    res.json({ 
      success: true, 
      message: 'Database migration completed successfully!' 
    });
  } catch (error) {
    console.error('Migration failed:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
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