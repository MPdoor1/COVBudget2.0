const { Client } = require('pg');
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');
require('dotenv').config();

async function getDbConnection() {
  let connectionString = process.env.DATABASE_URL;
  
  // Try to get connection string from Key Vault if not in env
  if (!connectionString && process.env.AZURE_KEY_VAULT_URL && process.env.DB_SECRET_NAME) {
    const credential = new DefaultAzureCredential();
    const secretClient = new SecretClient(process.env.AZURE_KEY_VAULT_URL, credential);
    const secret = await secretClient.getSecret(process.env.DB_SECRET_NAME);
    connectionString = secret.value;
  }
  
  if (!connectionString) {
    throw new Error('Database connection string not found');
  }
  
  const client = new Client({
    connectionString: connectionString,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
  
  await client.connect();
  return client;
}

async function createTables(client) {
  console.log('Creating database tables...');
  
  // Users table
  await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      name VARCHAR(255),
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      last_login TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Add missing columns to existing users table
  try {
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(255);`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;`);
    console.log('✅ Added missing columns to users table');
  } catch (error) {
    console.log('Note: Some columns may already exist:', error.message);
  }
  
  // Banks/Institutions table
  await client.query(`
    CREATE TABLE IF NOT EXISTS institutions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      plaid_institution_id VARCHAR(255),
      name VARCHAR(255) NOT NULL,
      url VARCHAR(255),
      primary_color VARCHAR(7),
      logo_url VARCHAR(500),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Bank Accounts table
  await client.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      institution_id UUID REFERENCES institutions(id) ON DELETE CASCADE,
      plaid_account_id VARCHAR(255) UNIQUE,
      account_name VARCHAR(255) NOT NULL,
      account_type VARCHAR(50) NOT NULL, -- checking, savings, credit, investment
      account_subtype VARCHAR(50),
      balance_current DECIMAL(12,2),
      balance_available DECIMAL(12,2),
      currency_code VARCHAR(3) DEFAULT 'USD',
      account_number_masked VARCHAR(50),
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Transactions table
  await client.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
      plaid_transaction_id VARCHAR(255) UNIQUE,
      amount DECIMAL(12,2) NOT NULL,
      date DATE NOT NULL,
      name VARCHAR(500) NOT NULL,
      merchant_name VARCHAR(255),
      category_primary VARCHAR(100),
      category_detailed VARCHAR(100),
      subcategory VARCHAR(100),
      account_owner VARCHAR(255),
      pending BOOLEAN DEFAULT FALSE,
      transaction_type VARCHAR(50), -- digital, place, special, unresolved
      location_address VARCHAR(500),
      location_city VARCHAR(100),
      location_region VARCHAR(100),
      location_country VARCHAR(100),
      location_postal_code VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Budget Categories table
  await client.query(`
    CREATE TABLE IF NOT EXISTS budget_categories (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      color_hex VARCHAR(7),
      icon VARCHAR(50),
      parent_category_id UUID REFERENCES budget_categories(id),
      is_expense BOOLEAN DEFAULT TRUE,
      sort_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Budgets table
  await client.query(`
    CREATE TABLE IF NOT EXISTS budgets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      category_id UUID REFERENCES budget_categories(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      amount DECIMAL(12,2) NOT NULL,
      period VARCHAR(20) DEFAULT 'monthly', -- monthly, weekly, yearly
      start_date DATE NOT NULL,
      end_date DATE,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Financial Goals table
  await client.query(`
    CREATE TABLE IF NOT EXISTS financial_goals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      target_amount DECIMAL(12,2) NOT NULL,
      current_amount DECIMAL(12,2) DEFAULT 0,
      target_date DATE,
      category VARCHAR(100), -- savings, debt, investment, emergency
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Transaction Rules table (for auto-categorization)
  await client.query(`
    CREATE TABLE IF NOT EXISTS transaction_rules (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      category_id UUID REFERENCES budget_categories(id) ON DELETE SET NULL,
      name VARCHAR(255) NOT NULL,
      condition_type VARCHAR(50) NOT NULL, -- contains, equals, starts_with, regex
      condition_value VARCHAR(500) NOT NULL,
      field_to_match VARCHAR(50) NOT NULL, -- name, merchant_name, category
      priority INTEGER DEFAULT 0,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Plaid Items table (for managing bank connections)
  await client.query(`
    CREATE TABLE IF NOT EXISTS plaid_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      institution_id UUID REFERENCES institutions(id) ON DELETE CASCADE,
      plaid_item_id VARCHAR(255) UNIQUE NOT NULL,
      access_token_encrypted TEXT NOT NULL,
      cursor VARCHAR(255), -- for incremental transaction sync
      webhook_url VARCHAR(500),
      is_active BOOLEAN DEFAULT TRUE,
      last_synced_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Create indexes for better performance
  await client.query(`
    CREATE INDEX IF NOT EXISTS idx_transactions_user_date ON transactions(user_id, date DESC);
    CREATE INDEX IF NOT EXISTS idx_transactions_account ON transactions(account_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_category ON transactions(category_primary);
    CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
    CREATE INDEX IF NOT EXISTS idx_budgets_user_category ON budgets(user_id, category_id);
  `);
  
  console.log('✅ Database tables created successfully');
}

async function insertDefaultData(client) {
  console.log('Inserting default data...');
  
  // Create default budget categories
  const defaultCategories = [
    { name: 'Food & Dining', description: 'Restaurants, groceries, food delivery', color_hex: '#FF6B6B', icon: 'restaurant', is_expense: true },
    { name: 'Transportation', description: 'Gas, public transport, rideshare', color_hex: '#4ECDC4', icon: 'directions_car', is_expense: true },
    { name: 'Shopping', description: 'Clothes, electronics, general retail', color_hex: '#45B7D1', icon: 'shopping_bag', is_expense: true },
    { name: 'Entertainment', description: 'Movies, games, hobbies', color_hex: '#96CEB4', icon: 'movie', is_expense: true },
    { name: 'Bills & Utilities', description: 'Rent, electricity, internet, phone', color_hex: '#FFEAA7', icon: 'receipt', is_expense: true },
    { name: 'Healthcare', description: 'Medical, dental, pharmacy', color_hex: '#DDA0DD', icon: 'local_hospital', is_expense: true },
    { name: 'Income', description: 'Salary, freelance, other income', color_hex: '#98D8C8', icon: 'attach_money', is_expense: false },
    { name: 'Savings', description: 'Emergency fund, investments', color_hex: '#F7DC6F', icon: 'savings', is_expense: false }
  ];
  
  // Create a system user for default categories
  await client.query(`
    INSERT INTO users (id, email, password_hash, first_name, last_name)
    SELECT '00000000-0000-0000-0000-000000000000'::uuid, 'system@covbudget.com', 'system', 'System', 'Default'
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE id = '00000000-0000-0000-0000-000000000000'::uuid)
  `);
  
  for (let i = 0; i < defaultCategories.length; i++) {
    const cat = defaultCategories[i];
    await client.query(`
      INSERT INTO budget_categories (user_id, name, description, color_hex, icon, is_expense, sort_order)
      SELECT '00000000-0000-0000-0000-000000000000'::uuid, $1::VARCHAR, $2::TEXT, $3::VARCHAR, $4::VARCHAR, $5::BOOLEAN, $6::INTEGER
      WHERE NOT EXISTS (SELECT 1 FROM budget_categories WHERE name = $1::VARCHAR AND user_id = '00000000-0000-0000-0000-000000000000'::uuid)
    `, [cat.name, cat.description, cat.color_hex, cat.icon, cat.is_expense, i]);
  }
  
  console.log('✅ Default data inserted successfully');
}

async function runMigrations() {
  let client;
  
  try {
    client = await getDbConnection();
    console.log('🔌 Connected to database');
    
    await createTables(client);
    await insertDefaultData(client);
    
    console.log('🎉 Database migration completed successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    if (client) {
      await client.end();
    }
  }
}

// Run migrations if called directly
if (require.main === module) {
  runMigrations();
}

module.exports = { runMigrations }; 