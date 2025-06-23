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

// Serve static assets but disable automatic index.html at root so we can control landing page
app.use(express.static('public', { index: false }));

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
        console.log('✅ Connected to database');
        
        // Ensure unique constraint exists for transaction deduplication
        try {
          await dbClient.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_unique_account_transaction 
            ON transactions(account_id, transaction_id) 
            WHERE transaction_id IS NOT NULL;
          `);
          console.log('✅ Transaction deduplication constraint verified');
        } catch (constraintError) {
          console.log('⚠️  Note: Could not create transaction constraint:', constraintError.message);
        }
      }
    }
  } catch (error) {
    console.log('❌ Database connection failed:', error.message);
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
  console.log('Mock query:', text.substring(0, 100) + '...', 'Params:', params?.slice(0, 3));
  
  // Handle INSERT INTO accounts with RETURNING
  if (text.includes('INSERT INTO accounts') && text.includes('RETURNING')) {
    const [userId, name, type, bankName, balance, isActive] = params;
    const newAccount = {
      id: 'mock-account-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
      user_id: userId,
      name,
      type,
      bank_name: bankName,
      balance: balance || 0,
      is_active: isActive !== false,
      created_at: new Date(),
      updated_at: new Date()
    };
    mockAccounts.push(newAccount);
    console.log('Created mock account:', newAccount);
    console.log('Total mock accounts:', mockAccounts.length);
    return { rows: [{ id: newAccount.id, name: newAccount.name }] };
  }
  
  // Handle INSERT INTO transactions with RETURNING
  if (text.includes('INSERT INTO transactions') && text.includes('RETURNING')) {
    const [userId, accountId, transactionId, amount, date, description, categoryPrimary, category, merchantName, currencyCode] = params;
    
    // Check for duplicate transaction_id
    const existingTransaction = mockTransactions.find(tx => 
      tx.account_id === accountId && tx.transaction_id === transactionId
    );
    
    if (existingTransaction) {
      console.log('Duplicate transaction skipped:', transactionId);
      return { rows: [] }; // ON CONFLICT DO NOTHING
    }
    
    const newTransaction = {
      id: 'mock-tx-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
      user_id: userId,
      account_id: accountId,
      transaction_id: transactionId,
      amount: parseFloat(amount),
      date: date,
      description: description,
      category_primary: categoryPrimary,
      category: category,
      merchant_name: merchantName,
      iso_currency_code: currencyCode,
      created_at: new Date(),
      updated_at: new Date()
    };
    mockTransactions.push(newTransaction);
    console.log('Created mock transaction:', { 
      id: newTransaction.id, 
      amount: newTransaction.amount, 
      description: newTransaction.description?.substring(0, 50) 
    });
    console.log('Total mock transactions:', mockTransactions.length);
    return { rows: [{ id: newTransaction.id }] };
  }
  
  // Handle SELECT from accounts
  if (text.includes('SELECT') && text.includes('accounts')) {
    const userId = params[0];
    console.log('Querying accounts for user:', userId);
    console.log('Available accounts:', mockAccounts.map(acc => ({ id: acc.id, user_id: acc.user_id, name: acc.name })));
    
    if (text.includes('WHERE id = $1 AND user_id = $2')) {
      // Account verification query
      const [accountId, userId] = params;
      const account = mockAccounts.find(acc => acc.id === accountId && acc.user_id === userId);
      console.log('Account verification result:', !!account);
      return { rows: account ? [{ id: account.id, name: account.name }] : [] };
    } else {
      // General account list query
      const userAccounts = mockAccounts.filter(acc => acc.user_id === userId && acc.is_active);
      console.log('Filtered accounts:', userAccounts.length);
      return { rows: userAccounts };
    }
  }
  
  // Handle SELECT from transactions
  if (text.includes('SELECT') && text.includes('transactions')) {
    const userId = params[0];
    console.log('Querying transactions for user:', userId);
    console.log('Available transactions:', mockTransactions.map(tx => ({ id: tx.id, user_id: tx.user_id, amount: tx.amount })));
    
    // Add account name to transactions for display
    const userTransactions = mockTransactions
      .filter(tx => tx.user_id === userId)
      .map(tx => {
        const account = mockAccounts.find(acc => acc.id === tx.account_id);
        return {
          ...tx,
          account_name: account ? account.name : 'Unknown Account',
          institution_name: account ? account.bank_name : 'Unknown Bank'
        };
      });
    
    console.log('Filtered transactions:', userTransactions.length);
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
  
  // Default response for other queries
  console.log('Unhandled query type');
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
    console.log('JWT decoded successfully:', { userId: decoded.userId, email: decoded.email });
    req.user = decoded;
    next();
  } catch (error) {
    // In development mode, allow a mock user for testing
    if (process.env.NODE_ENV === 'development' && token === 'mock-token') {
      req.user = { userId: 'mock-user-123', email: 'test@example.com' };
      return next();
    }
    if (token === 'mock-token') {
      try {
        // Ensure there is a persistent demo user so foreign-key constraints succeed
        if (dbClient) {
          const mockEmail = 'demo@example.com';
          // Fetch existing demo user by email
          const existing = await dbClient.query('SELECT id FROM users WHERE email = $1 LIMIT 1', [mockEmail]);
          let demoId;
          if (existing.rows.length) {
            demoId = existing.rows[0].id;
          } else {
            // Insert minimal record (works for UUID or SERIAL PKs)
            const inserted = await dbClient.query(
              `INSERT INTO users (name, email, password_hash, created_at, updated_at)
               VALUES ('Demo User', $1, 'mock-hash', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
               RETURNING id`,
              [mockEmail]
            );
            demoId = inserted.rows[0].id;
          }
          req.user = { userId: demoId, email: mockEmail };
        } else {
          // No DB (e.g. local dev) – keep hard-coded id
          req.user = { userId: 'mock-user-123', email: 'test@example.com' };
        }
      } catch (mockErr) {
        console.error('Failed to ensure demo user exists:', mockErr.message);
        req.user = { userId: 'mock-user-123', email: 'test@example.com' };
      }
      return next();
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  // Serve the new gold & black dashboard
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
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

// Get users for debugging (REMOVE AFTER DEBUGGING)
app.get('/api/debug-users', async (req, res) => {
  try {
    const result = await query('SELECT id, email, name, created_at FROM users ORDER BY created_at DESC LIMIT 10');
    res.json({
      success: true,
      users: result.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Debug account creation step by step
app.post('/api/debug-account', async (req, res) => {
  try {
    const { name, type, bank_name, balance, user_id } = req.body;
    
    // Step 1: Test basic connection
    const testResult = await query('SELECT NOW() as time, $1 as test_param', ['test']);
    
    // Step 2: Check if user exists
    const userCheck = await query('SELECT id, email FROM users WHERE id = $1', [user_id]);
    
    // Step 3: Check accounts table structure
    const tableStructure = await query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'accounts' 
      ORDER BY ordinal_position
    `);
    
    // Step 4: Try the actual insert
    let insertResult = null;
    let insertError = null;
    try {
      insertResult = await query(`
        INSERT INTO accounts (user_id, name, account_name, type, account_type, bank_name, balance, is_active)
        VALUES ($1, $2, $2, $3, $3, $4, $5, true)
        RETURNING *
      `, [user_id, name, type, bank_name, balance || 0]);
    } catch (err) {
      insertError = {
        message: err.message,
        code: err.code,
        constraint: err.constraint,
        table: err.table,
        column: err.column,
        detail: err.detail
      };
    }
    
    res.json({
      success: !insertError,
      steps: {
        connection: testResult.rows[0],
        userExists: userCheck.rows.length > 0,
        user: userCheck.rows[0],
        tableStructure: tableStructure.rows,
        insertResult: insertResult ? insertResult.rows[0] : null,
        insertError: insertError
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: error.message,
        code: error.code,
        constraint: error.constraint,
        table: error.table,
        column: error.column,
        detail: error.detail,
        stack: error.stack
      }
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
      INSERT INTO accounts (user_id, name, account_name, type, account_type, bank_name, balance, is_active)
      VALUES ($1, $2, $2, $3, $3, $4, $5, true)
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
      details: error.message,
      code: error.code,
      constraint: error.constraint,
      table: error.table,
      column: error.column,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Update account
app.put('/api/accounts/:id', authenticateToken, async (req, res) => {
  try {
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    if (!dbClient && process.env.NODE_ENV !== 'development') {
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
    console.log('=== STATEMENT UPLOAD START ===');
    console.log('User:', req.user);
    console.log('File:', req.file ? req.file.originalname : 'No file');
    console.log('Body:', req.body);

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { account_id, account_name, format = 'wells_fargo' } = req.body;
    const filePath = req.file.path;
    const fileExt = path.extname(req.file.originalname).toLowerCase();

    console.log('Processing statement upload:', req.file.originalname);
    console.log('Format:', format);
    console.log('Account ID:', account_id);
    console.log('Account Name:', account_name);

    let transactions = [];

    try {
      if (fileExt === '.csv') {
        transactions = await parseCSVFile(filePath, format);
      } else if (fileExt === '.xlsx' || fileExt === '.xls') {
        transactions = await parseExcelFile(filePath, format);
      } else {
        throw new Error('Unsupported file format. Please upload CSV or Excel files.');
      }

      console.log(`Parsed ${transactions.length} transactions from file`);

      if (transactions.length === 0) {
        throw new Error('No valid transactions found in file');
      }

      // Determine account to use
      let targetAccountId = account_id;
      let targetAccountName = account_name || 'Uploaded Account';

      // If no account_id provided, create a new account
      if (!targetAccountId) {
        console.log('Creating new account for upload...');
        
        const accountResult = await query(`
          INSERT INTO accounts (
            user_id, name, type, bank_name, balance, is_active, created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          RETURNING id, name
        `, [
          req.user.userId,
          targetAccountName,
          'checking',
          'Wells Fargo', // Default bank name
          0,
          true
        ]);

        if (accountResult.rows.length > 0) {
          targetAccountId = accountResult.rows[0].id;
          targetAccountName = accountResult.rows[0].name;
          console.log('Created account:', targetAccountId, targetAccountName);
        } else {
          throw new Error('Failed to create account for transactions');
        }
      } else {
        // Verify account exists and belongs to user
        const accountCheck = await query(
          'SELECT id, name FROM accounts WHERE id = $1 AND user_id = $2',
          [targetAccountId, req.user.userId]
        );
        
        if (accountCheck.rows.length === 0) {
          throw new Error('Account not found or access denied');
        }
        
        targetAccountName = accountCheck.rows[0].name;
      }

      console.log('Using account:', targetAccountId, targetAccountName);

      // Insert transactions
      let insertedCount = 0;
      const insertErrors = [];

      for (let i = 0; i < transactions.length; i++) {
        const transaction = transactions[i];
        
        try {
          // Create unique transaction ID
          const transactionId = `upload_${Date.now()}_${i}_${Math.random().toString(36).substr(2, 9)}`;
          
          // Validate transaction data
          if (!transaction.date || !transaction.description || transaction.amount === undefined || transaction.amount === null) {
            console.log('Skipping invalid transaction:', transaction);
            continue;
          }

          // Ensure description is not too long for database
          const description = String(transaction.description).substring(0, 500);
          const category = String(transaction.category || 'Other').substring(0, 100);
          const merchant = String(transaction.merchant || '').substring(0, 100);

          console.log(`Inserting transaction ${i + 1}:`, {
            id: transactionId,
            amount: transaction.amount,
            date: transaction.date,
            description: description.substring(0, 50) + '...'
          });

          const result = await query(`
            INSERT INTO transactions (
              user_id, account_id, transaction_id, amount, date, description, 
              category_primary, category, merchant_name, 
              iso_currency_code, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (account_id, transaction_id) DO NOTHING
            RETURNING id
          `, [
            req.user.userId,
            targetAccountId,
            transactionId,
            transaction.amount,
            transaction.date,
            description,
            category,
            category,
            merchant,
            'USD'
          ]);

          if (result.rows.length > 0) {
            insertedCount++;
            console.log(`✓ Transaction ${i + 1} inserted successfully`);
          } else {
            console.log(`⚠ Transaction ${i + 1} skipped (duplicate)`);
          }

        } catch (insertError) {
          console.error(`✗ Failed to insert transaction ${i + 1}:`, insertError.message);
          console.error('Transaction data:', transaction);
          console.error('Full error:', insertError);
          insertErrors.push(`Transaction ${i + 1}: ${insertError.message}`);
        }
      }

      // Calculate date range
      const dates = transactions.map(t => new Date(t.date)).sort((a, b) => a - b);
      const dateRange = dates.length > 0 
        ? `${dates[0].toISOString().split('T')[0]} to ${dates[dates.length - 1].toISOString().split('T')[0]}`
        : 'Unknown';

      console.log(`=== UPLOAD COMPLETE ===`);
      console.log(`Total parsed: ${transactions.length}`);
      console.log(`Successfully inserted: ${insertedCount}`);
      console.log(`Errors: ${insertErrors.length}`);

      // Clean up uploaded file
      try {
        fs.unlinkSync(filePath);
      } catch (cleanupError) {
        console.log('File cleanup warning:', cleanupError.message);
      }

      // Return success response
      const response = {
        success: true,
        transactions_count: insertedCount,
        transactionCount: insertedCount, // For backward compatibility
        totalParsed: transactions.length,
        accountId: targetAccountId,
        accountName: targetAccountName,
        dateRange: dateRange,
        message: `Successfully processed ${insertedCount} transactions`,
        errors: insertErrors.length > 0 ? insertErrors : undefined
      };

      console.log('Response:', response);
      res.json(response);

    } catch (parseError) {
      console.error('File parsing error:', parseError);
      
      // Clean up uploaded file
      try {
        fs.unlinkSync(filePath);
      } catch (cleanupError) {
        console.log('File cleanup warning:', cleanupError.message);
      }

      res.status(400).json({
        error: 'Failed to parse file: ' + parseError.message,
        details: parseError.stack
      });
    }

  } catch (error) {
    console.error('Upload endpoint error:', error);
    
    // Clean up uploaded file if it exists
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (cleanupError) {
        console.log('File cleanup warning:', cleanupError.message);
      }
    }

    res.status(500).json({
      error: 'Upload failed: ' + error.message,
      details: error.stack
    });
  }
});

// Helper function to parse CSV files
function parseCSVFile(filePath, format = null) {
  return new Promise((resolve, reject) => {
    const rows = [];
    let rowCount = 0;
    let hasHeaders = false;
    
    console.log(`🧠 Using intelligent universal CSV parser (format hint: ${format || 'auto-detect'})`);
    
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (row) => {
        try {
          rowCount++;
          
          // Check if this looks like a header row
          if (rowCount === 1) {
            const values = Object.values(row);
            const hasDateValue = values.some(val => val && val.toString().match(/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/));
            hasHeaders = !hasDateValue;
            console.log('Header detection:', hasHeaders ? 'Headers detected' : 'No headers, data starts immediately');
          }
          
          // Skip header row if detected
          if (hasHeaders && rowCount === 1) {
            console.log('Skipping header row');
            return;
          }
          
          // Collect all data rows for intelligent analysis
          rows.push(row);
          
        } catch (error) {
          console.warn('Failed to process row:', error.message);
        }
      })
      .on('end', () => {
        console.log(`📊 Collected ${rows.length} data rows for analysis`);
        
        try {
          // Use intelligent universal parser
          const transactions = analyzeAndParseCSV(rows);
          console.log(`✅ Universal parsing complete: ${transactions.length} transactions extracted`);
          resolve(transactions);
        } catch (parseError) {
          console.error('❌ Intelligent parsing failed:', parseError);
          reject(parseError);
        }
      })
      .on('error', reject);
  });
}

// Helper function to parse Excel files
function parseExcelFile(filePath, format = null) {
  try {
    console.log(`🧠 Using intelligent universal Excel parser (format hint: ${format || 'auto-detect'})`);
    
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const jsonData = xlsx.utils.sheet_to_json(worksheet);
    
    console.log(`📊 Collected ${jsonData.length} rows from Excel file for analysis`);
    
    // Use intelligent universal parser
    const transactions = analyzeAndParseCSV(jsonData);
    console.log(`✅ Universal Excel parsing complete: ${transactions.length} transactions extracted`);
    
    return transactions;
  } catch (error) {
    throw new Error(`Failed to parse Excel file: ${error.message}`);
  }
}

// Helper function to parse Wells Fargo specific format
function parseWellsFargoRow(row, rowIndex) {
  console.log(`Parsing Wells Fargo row ${rowIndex}:`, row);
  
  try {
    const keys = Object.keys(row);
    // Clean and normalize values: trim whitespace and remove surrounding quotes
    const values = Object.values(row).map(val => {
      if (val === null || val === undefined) return '';
      const str = String(val).trim();
      // Remove surrounding quotes if present
      return str.replace(/^["']|["']$/g, '');
    });
    
    console.log('Row keys:', keys);
    console.log('Row values:', values);
    
    let date = null;
    let amount = null;
    let description = '';
    
    // Wells Fargo CSV format: Date, Amount, *, , Description
    // Expected structure: [Date, Amount, *, Empty, Description]
    
    // Extract date from first column (index 0)
    if (values.length > 0 && values[0]) {
      const dateStr = values[0];
      console.log(`Found date in column A (0): ${dateStr}`);
      try {
        date = parseDate(dateStr);
      } catch (dateError) {
        console.warn(`Failed to parse date "${dateStr}":`, dateError.message);
        return null;
      }
    }
    
    // Extract amount from second column (index 1)
    if (values.length > 1 && values[1]) {
      const amountStr = String(values[1]).replace(/[,$\s]/g, '');
      amount = parseFloat(amountStr);
      console.log(`Found amount in column B (1): ${values[1]} -> parsed as: ${amount}`);
      
      if (isNaN(amount)) {
        console.warn(`Invalid amount in column B: ${values[1]}`);
        return null;
      }
    }
    
    // Extract description from the last column that contains meaningful text
    // In Wells Fargo format, description is typically in the 5th column (index 4)
    if (values.length >= 5 && values[4]) {
      const desc = String(values[4]).trim();
      if (desc && desc !== '*' && desc !== '') {
        description = desc;
        console.log(`Found description in column E (4): ${description}`);
      }
    }
    
    // If no description found in column 4, look for the longest meaningful text field
    if (!description) {
      let longestText = '';
      let longestIndex = -1;
      
      values.forEach((val, idx) => {
        if (val && typeof val === 'string') {
          const cleanVal = val.trim();
          
          // Skip if it's the date, amount, asterisk, or empty
          if (idx === 0 || idx === 1 || cleanVal === '*' || cleanVal === '') {
            return;
          }
          
          // Skip if it's purely numeric (likely misplaced amount)
          const isNumeric = cleanVal.replace(/[,$-]/g, '').match(/^\d+(\.\d+)?$/);
          if (isNumeric) {
            return;
          }
          
          // Skip if it's a date
          const isDate = cleanVal.match(/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/);
          if (isDate) {
            return;
          }
          
          // Keep the longest meaningful text
          if (cleanVal.length > longestText.length && cleanVal.length > 5) {
            longestText = cleanVal;
            longestIndex = idx;
            description = cleanVal;
          }
        }
      });
      
      if (description) {
        console.log(`Found description in column ${longestIndex} (fallback): ${description}`);
      }
    }
    
    console.log(`Wells Fargo parsed: date=${date}, amount=${amount}, description=${description}`);
    
    // Validate the parsed data
    const isValidDate = date && !isNaN(new Date(date).getTime());
    const isValidAmount = !isNaN(amount) && amount !== 0;
    const isValidDescription = description && description.length > 1;
    
    console.log(`Validation check: date=${isValidDate}, amount=${isValidAmount}, amount!=0=${amount !== 0}, description=${isValidDescription}, desc.length=${description ? description.length : 0}`);
    
    if (isValidDate && isValidAmount && isValidDescription) {
      const category = categorizeTransaction(description);
      const transaction = {
        date: date,
        description: description,
        amount: amount,
        category: category,
        merchant: extractMerchant(description)
      };
      console.log(`✓ Valid transaction created:`, transaction);
      return transaction;
    }
    
    console.log(`✗ Transaction validation failed`);
    return null;
    
  } catch (error) {
    console.warn(`Failed to parse Wells Fargo row ${rowIndex}:`, error.message);
    return null;
  }
}

// Helper function to parse individual transaction rows
function parseTransactionRow(row) {
  // Try to find date column (various possible names)
  const dateFields = [
    'date', 'Date', 'DATE', 'Transaction Date', 'Posted Date', 'posting_date',
    'Post Date', 'Posting Date', 'Trans Date', 'Settlement Date'
  ];
  const descFields = [
    'description', 'Description', 'DESCRIPTION', 'Memo', 'memo', 'Transaction Description',
    'Details', 'Payee', 'Transaction', 'Reference', 'Merchant', 'Transaction Details'
  ];
  const amountFields = [
    'amount', 'Amount', 'AMOUNT', 'Debit', 'Credit', 'Transaction Amount',
    'Withdrawal', 'Deposit', 'Balance Change', 'Net Amount'
  ];

  let date = null;
  let description = null;
  let amount = null;

  // Debug: log the row structure
  const keys = Object.keys(row);
  const values = Object.values(row);
  console.log('Row keys:', keys);
  console.log('Row values:', values);

  // Check if this is a headerless CSV (columns accessed by index)
  const isHeaderless = keys.every(key => /^\d+$/.test(key) || key.startsWith('column'));
  
  if (isHeaderless && values.length >= 3) {
    // Assume format: Date, Amount, Description (most common bank format)
    console.log('Detected headerless CSV format');
    try {
      // For headerless CSV, the values array contains the actual data
      // The keys might be auto-generated column names like '0', '1', '2' or column headers from first row
      date = parseDate(values[0]);
      amount = parseFloat(String(values[1]).replace(/[,$\s]/g, ''));
      description = String(values[2]).trim();
      
      console.log('Parsed headerless:', { date, amount, description });
      
      if (date && !isNaN(amount) && description) {
        const category = categorizeTransaction(description);
        return {
          date: date,
          description: description,
          amount: amount,
          category: category,
          merchant: extractMerchant(description)
        };
      }
    } catch (error) {
      console.warn('Failed to parse headerless format:', error.message);
    }
  }

  // If headerless parsing failed, try to parse as if columns are mixed up
  if (values.length >= 3) {
    console.log('Trying alternative column parsing');
    for (let i = 0; i < values.length; i++) {
      for (let j = 0; j < values.length; j++) {
        for (let k = 0; k < values.length; k++) {
          if (i !== j && j !== k && i !== k) {
            try {
              const testDate = parseDate(values[i]);
              const testAmount = parseFloat(String(values[j]).replace(/[,$\s]/g, ''));
              const testDesc = String(values[k]).trim();
              
              if (testDate && !isNaN(testAmount) && testDesc && testDesc.length > 3) {
                console.log(`Found valid combination: date=${values[i]}, amount=${values[j]}, desc=${values[k]}`);
                const category = categorizeTransaction(testDesc);
                return {
                  date: testDate,
                  description: testDesc,
                  amount: testAmount,
                  category: category,
                  merchant: extractMerchant(testDesc)
                };
              }
            } catch (error) {
              // Continue trying other combinations
            }
          }
        }
      }
    }
  }

  // Find date
  for (const field of dateFields) {
    if (row[field]) {
      try {
        date = parseDate(row[field]);
        break;
      } catch (error) {
        console.warn(`Failed to parse date from field ${field}:`, row[field]);
      }
    }
  }

  // If no standard date field found, try the first column that looks like a date
  if (!date) {
    for (const [key, value] of Object.entries(row)) {
      if (value && typeof value === 'string' && value.match(/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/)) {
        try {
          date = parseDate(value);
          console.log(`Found date in column "${key}":`, value);
          break;
        } catch (error) {
          // Continue searching
        }
      }
    }
  }

  // Find description
  for (const field of descFields) {
    if (row[field]) {
      description = String(row[field]).trim();
      break;
    }
  }

  // If no standard description field found, use the longest text field
  if (!description) {
    let longestField = '';
    for (const [key, value] of Object.entries(row)) {
      if (value && typeof value === 'string' && value.length > longestField.length && 
          !key.toLowerCase().includes('amount') && !key.toLowerCase().includes('balance')) {
        longestField = value;
        description = value.trim();
      }
    }
    if (description) {
      console.log('Using longest text field as description:', description);
    }
  }

  // Find amount
  for (const field of amountFields) {
    if (row[field] !== undefined && row[field] !== '') {
      const cleanAmount = String(row[field]).replace(/[,$\s]/g, '');
      amount = parseFloat(cleanAmount);
      if (!isNaN(amount)) {
        break;
      }
    }
  }

  // Handle separate debit/credit columns
  if (amount === null || isNaN(amount)) {
    const debit = parseFloat(String(row['Debit'] || row['debit'] || row['Withdrawal'] || '0').replace(/[,$\s]/g, ''));
    const credit = parseFloat(String(row['Credit'] || row['credit'] || row['Deposit'] || '0').replace(/[,$\s]/g, ''));
    
    if (!isNaN(debit) && debit !== 0) {
      amount = -Math.abs(debit); // Debits are negative
    } else if (!isNaN(credit) && credit !== 0) {
      amount = Math.abs(credit); // Credits are positive
    }
  }

  // If still no amount found, try to find any numeric field
  if (amount === null || isNaN(amount)) {
    for (const [key, value] of Object.entries(row)) {
      if (value && !isNaN(parseFloat(String(value).replace(/[,$\s]/g, '')))) {
        const testAmount = parseFloat(String(value).replace(/[,$\s]/g, ''));
        if (Math.abs(testAmount) > 0.01) { // Ignore very small amounts that might be fees/IDs
          amount = testAmount;
          console.log(`Found amount in column "${key}":`, testAmount);
          break;
        }
      }
    }
  }

  if (!date || !description || amount === null || isNaN(amount)) {
    console.warn('Skipping invalid row:', { date, description, amount, availableFields: Object.keys(row) });
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

// Helper function to parse various date formats
function parseDate(dateStr) {
  if (!dateStr) return null;
  
  // Clean the date string
  const cleaned = String(dateStr).trim();
  
  // Try different date formats
  const formats = [
    // MM/DD/YYYY
    /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/,
    // MM/DD/YY
    /^(\d{1,2})\/(\d{1,2})\/(\d{2})$/,
    // MM-DD-YYYY
    /^(\d{1,2})-(\d{1,2})-(\d{4})$/,
    // MM-DD-YY
    /^(\d{1,2})-(\d{1,2})-(\d{2})$/,
    // YYYY-MM-DD (ISO format)
    /^(\d{4})-(\d{1,2})-(\d{1,2})$/,
    // DD/MM/YYYY (European format)
    /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/,
  ];
  
  // Try MM/DD/YYYY or MM/DD/YY format first (most common for US banks)
  let match = cleaned.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);
  if (match) {
    let [, month, day, year] = match;
    
    // Convert 2-digit year to 4-digit
    if (year.length === 2) {
      const currentYear = new Date().getFullYear();
      const currentCentury = Math.floor(currentYear / 100) * 100;
      year = parseInt(year) <= 30 ? currentCentury + 100 + parseInt(year) : currentCentury + parseInt(year);
    }
    
    // Create date object and validate
    const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
    
    // Check if the date is valid
    if (date.getFullYear() == year && date.getMonth() == month - 1 && date.getDate() == day) {
      // Return in YYYY-MM-DD format for database
      return date.toISOString().split('T')[0];
    }
  }
  
  // Try MM-DD-YYYY or MM-DD-YY format
  match = cleaned.match(/^(\d{1,2})-(\d{1,2})-(\d{2,4})$/);
  if (match) {
    let [, month, day, year] = match;
    
    // Convert 2-digit year to 4-digit
    if (year.length === 2) {
      const currentYear = new Date().getFullYear();
      const currentCentury = Math.floor(currentYear / 100) * 100;
      year = parseInt(year) <= 30 ? currentCentury + 100 + parseInt(year) : currentCentury + parseInt(year);
    }
    
    // Create date object and validate
    const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
    
    // Check if the date is valid
    if (date.getFullYear() == year && date.getMonth() == month - 1 && date.getDate() == day) {
      // Return in YYYY-MM-DD format for database
      return date.toISOString().split('T')[0];
    }
  }
  
  // Try YYYY-MM-DD format (ISO)
  match = cleaned.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (match) {
    const [, year, month, day] = match;
    const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
    
    // Check if the date is valid
    if (date.getFullYear() == year && date.getMonth() == month - 1 && date.getDate() == day) {
      // Already in correct format
      return cleaned;
    }
  }
  
  // Try parsing as a regular Date object (fallback)
  try {
    const date = new Date(cleaned);
    if (!isNaN(date.getTime())) {
      // Return in YYYY-MM-DD format for database
      return date.toISOString().split('T')[0];
    }
  } catch (error) {
    // Continue to throw error below
  }
  
  throw new Error(`Unable to parse date: ${dateStr}`);
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

// Universal Intelligent CSV Parser
function analyzeAndParseCSV(rows) {
    console.log('🧠 Starting intelligent CSV analysis...');
    
    if (!rows || rows.length === 0) {
        throw new Error('No data rows to analyze');
    }
    
    // Sample the first few rows for analysis
    const sampleSize = Math.min(10, rows.length);
    const sampleRows = rows.slice(0, sampleSize);
    
    console.log(`Analyzing ${sampleSize} sample rows from ${rows.length} total rows`);
    
    // Get column structure from first row
    const firstRow = sampleRows[0];
    const columnKeys = Object.keys(firstRow);
    const columnCount = columnKeys.length;
    
    console.log(`Found ${columnCount} columns:`, columnKeys);
    
    // Analyze each column to determine its type
    const columnAnalysis = analyzeColumns(sampleRows, columnKeys);
    
    // Identify the key columns we need
    const columnMapping = identifyKeyColumns(columnAnalysis);
    
    console.log('Column mapping identified:', columnMapping);
    
    // Parse all rows using the identified mapping
    const transactions = [];
    let successCount = 0;
    let failCount = 0;
    
    for (let i = 0; i < rows.length; i++) {
        try {
            const transaction = parseRowWithMapping(rows[i], columnMapping, i + 1);
            if (transaction) {
                transactions.push(transaction);
                successCount++;
            } else {
                failCount++;
            }
        } catch (error) {
            console.log(`❌ Failed to parse row ${i + 1}:`, error.message);
            failCount++;
        }
    }
    
    console.log(`✅ Intelligent parsing complete: ${successCount} success, ${failCount} failed`);
    return transactions;
}

function analyzeColumns(sampleRows, columnKeys) {
    const analysis = {};
    
    columnKeys.forEach((key, index) => {
        analysis[key] = {
            index: index,
            key: key,
            samples: [],
            types: {
                date: 0,
                amount: 0,
                description: 0,
                empty: 0,
                other: 0
            },
            patterns: {
                hasNumbers: 0,
                hasLetters: 0,
                hasSymbols: 0,
                isNumeric: 0,
                isDate: 0,
                isEmpty: 0,
                avgLength: 0
            }
        };
        
        // Collect samples and analyze patterns
        let totalLength = 0;
        sampleRows.forEach(row => {
            const value = String(row[key] || '').trim();
            analysis[key].samples.push(value);
            
            totalLength += value.length;
            
            // Pattern detection
            if (!value || value === '') {
                analysis[key].patterns.isEmpty++;
                analysis[key].types.empty++;
            } else {
                if (/\d/.test(value)) analysis[key].patterns.hasNumbers++;
                if (/[a-zA-Z]/.test(value)) analysis[key].patterns.hasLetters++;
                if (/[^a-zA-Z0-9\s]/.test(value)) analysis[key].patterns.hasSymbols++;
                
                // Check if it's purely numeric (amount)
                if (/^-?\$?\d+\.?\d*$/.test(value.replace(/,/g, ''))) {
                    analysis[key].patterns.isNumeric++;
                    analysis[key].types.amount++;
                }
                
                // Check if it's a date
                if (isLikelyDate(value)) {
                    analysis[key].patterns.isDate++;
                    analysis[key].types.date++;
                }
                
                // Check if it's descriptive text
                if (value.length > 10 && /[a-zA-Z]/.test(value)) {
                    analysis[key].types.description++;
                } else if (value.length > 0) {
                    analysis[key].types.other++;
                }
            }
        });
        
        analysis[key].patterns.avgLength = totalLength / sampleRows.length;
    });
    
    return analysis;
}

function isLikelyDate(value) {
    // Common date patterns
    const datePatterns = [
        /^\d{1,2}\/\d{1,2}\/\d{2,4}$/,     // MM/DD/YYYY or M/D/YY
        /^\d{1,2}-\d{1,2}-\d{2,4}$/,      // MM-DD-YYYY
        /^\d{4}-\d{1,2}-\d{1,2}$/,        // YYYY-MM-DD
        /^\d{1,2}\/\d{1,2}\/\d{4}$/,      // MM/DD/YYYY
        /^\d{2}\/\d{2}\/\d{4}$/,          // MM/DD/YYYY
    ];
    
    return datePatterns.some(pattern => pattern.test(value));
}

function identifyKeyColumns(analysis) {
    const mapping = {
        date: null,
        amount: null,
        description: null
    };
    
    const columns = Object.keys(analysis);
    
    // Find date column - highest date score
    let bestDateScore = 0;
    columns.forEach(key => {
        const col = analysis[key];
        const dateScore = col.types.date + (col.patterns.isDate * 2);
        if (dateScore > bestDateScore) {
            bestDateScore = dateScore;
            mapping.date = key;
        }
    });
    
    // Find amount column - highest numeric score, not the date column
    let bestAmountScore = 0;
    columns.forEach(key => {
        if (key === mapping.date) return; // Skip date column
        
        const col = analysis[key];
        const amountScore = col.types.amount + (col.patterns.isNumeric * 2) + 
                           (col.patterns.hasSymbols * 0.5); // $ signs, commas
        if (amountScore > bestAmountScore) {
            bestAmountScore = amountScore;
            mapping.amount = key;
        }
    });
    
    // Find description column - longest average text, not date or amount
    let bestDescScore = 0;
    columns.forEach(key => {
        if (key === mapping.date || key === mapping.amount) return;
        
        const col = analysis[key];
        const descScore = col.types.description + 
                         (col.patterns.avgLength / 10) + 
                         (col.patterns.hasLetters * 2) -
                         (col.patterns.isEmpty * 2);
        
        if (descScore > bestDescScore) {
            bestDescScore = descScore;
            mapping.description = key;
        }
    });
    
    // Fallback logic if we couldn't identify columns
    if (!mapping.date) {
        // Try to find date by position (often first column)
        mapping.date = columns[0];
    }
    
    if (!mapping.amount) {
        // Look for any column with numbers
        for (const key of columns) {
            if (key !== mapping.date && analysis[key].patterns.hasNumbers > 0) {
                mapping.amount = key;
                break;
            }
        }
    }
    
    if (!mapping.description) {
        // Use the longest text column
        let maxLength = 0;
        for (const key of columns) {
            if (key !== mapping.date && key !== mapping.amount) {
                if (analysis[key].patterns.avgLength > maxLength) {
                    maxLength = analysis[key].patterns.avgLength;
                    mapping.description = key;
                }
            }
        }
    }
    
    return mapping;
}

function parseRowWithMapping(row, mapping, rowNumber) {
    try {
        // Extract values using the mapping
        const dateValue = row[mapping.date];
        const amountValue = row[mapping.amount];
        const descValue = row[mapping.description];
        
        console.log(`Parsing row ${rowNumber}:`, {
            date: `${mapping.date} = "${dateValue}"`,
            amount: `${mapping.amount} = "${amountValue}"`,
            description: `${mapping.description} = "${descValue}"`
        });
        
        // Parse date
        const parsedDate = parseFlexibleDate(dateValue);
        if (!parsedDate) {
            console.log(`❌ Row ${rowNumber}: Invalid date "${dateValue}"`);
            return null;
        }
        
        // Parse amount
        const parsedAmount = parseFlexibleAmount(amountValue);
        if (parsedAmount === null || parsedAmount === 0) {
            console.log(`❌ Row ${rowNumber}: Invalid amount "${amountValue}"`);
            return null;
        }
        
        // Parse description
        const description = String(descValue || '').trim();
        if (!description || description.length < 3) {
            console.log(`❌ Row ${rowNumber}: Invalid description "${description}"`);
            return null;
        }
        
        // Extract merchant from description
        const merchant = extractMerchant(description);
        
        const transaction = {
            date: parsedDate,
            description: description,
            amount: parsedAmount,
            category: 'Other',
            merchant: merchant
        };
        
        console.log(`✅ Row ${rowNumber} parsed successfully:`, transaction);
        return transaction;
        
    } catch (error) {
        console.log(`❌ Row ${rowNumber} parsing error:`, error.message);
        return null;
    }
}

function parseFlexibleDate(dateStr) {
    if (!dateStr) return null;
    
    const cleaned = String(dateStr).trim();
    if (!cleaned) return null;
    
    // Try various date formats
    const formats = [
        // MM/DD/YYYY variants
        /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/,
        /^(\d{1,2})\/(\d{1,2})\/(\d{2})$/,
        // MM-DD-YYYY variants  
        /^(\d{1,2})-(\d{1,2})-(\d{4})$/,
        /^(\d{1,2})-(\d{1,2})-(\d{2})$/,
        // YYYY-MM-DD
        /^(\d{4})-(\d{1,2})-(\d{1,2})$/,
    ];
    
    for (const format of formats) {
        const match = cleaned.match(format);
        if (match) {
            let year, month, day;
            
            if (format.source.includes('(\\d{4})')) {
                // Has 4-digit year
                if (format.source.startsWith('^(\\d{4})')) {
                    // YYYY-MM-DD
                    [, year, month, day] = match;
                } else {
                    // MM/DD/YYYY or MM-DD-YYYY
                    [, month, day, year] = match;
                }
            } else {
                // 2-digit year - assume 20XX
                [, month, day, year] = match;
                year = '20' + year;
            }
            
            year = parseInt(year);
            month = parseInt(month);
            day = parseInt(day);
            
            // Validate ranges
            if (month >= 1 && month <= 12 && day >= 1 && day <= 31) {
                return `${year}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
            }
        }
    }
    
    // Try JavaScript Date parsing as fallback
    try {
        const date = new Date(cleaned);
        if (!isNaN(date.getTime())) {
            return date.toISOString().split('T')[0];
        }
    } catch (e) {
        // Ignore
    }
    
    return null;
}

function parseFlexibleAmount(amountStr) {
    if (!amountStr) return null;
    
    let cleaned = String(amountStr).trim();
    if (!cleaned) return null;
    
    // Remove common currency symbols and formatting
    cleaned = cleaned.replace(/[$,\s]/g, '');
    
    // Handle parentheses as negative (accounting format)
    if (cleaned.startsWith('(') && cleaned.endsWith(')')) {
        cleaned = '-' + cleaned.slice(1, -1);
    }
    
    // Try to parse as number
    const parsed = parseFloat(cleaned);
    
    if (isNaN(parsed)) {
        return null;
    }
    
    return parsed;
}

function extractMerchant(description) {
    if (!description) return 'Unknown';
    
    // Common patterns to extract merchant names
    const patterns = [
        /^([A-Z][A-Z\s&]+?)(?:\s+\d|\s+#|\s+ON\s|\s+REF|\s+AUTH)/,  // MERCHANT NAME followed by numbers/keywords
        /^([A-Z][A-Z\s&]{3,}?)(?:\s+[A-Z]{2}\s|\s+\d)/,            // MERCHANT NAME followed by state or numbers
        /^(.*?)\s+(?:PURCHASE|PAYMENT|TRANSFER|WITHDRAWAL)/i,        // Text before transaction type
        /^([^0-9#]{4,}?)(?:\s+[0-9#])/,                            // Non-numeric text before numbers
    ];
    
    for (const pattern of patterns) {
        const match = description.match(pattern);
        if (match) {
            return match[1].trim();
        }
    }
    
    // Fallback: take first few words
    const words = description.split(/\s+/);
    if (words.length >= 2) {
        return words.slice(0, 2).join(' ');
    }
    
    return words[0] || 'Unknown';
}