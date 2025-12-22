require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const { Pool } = require('pg');

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create Prisma adapter with pg pool
const adapter = new PrismaPg(pool);

// Create Prisma client with adapter (required for Prisma 7)
const prisma = new PrismaClient({
  adapter,
  log: process.env.NODE_ENV === 'development' ? ['info', 'warn', 'error'] : ['error'],
});

let initialized = false;

async function initDB() {
  if (initialized) return prisma;

  try {
    // Test connection
    await prisma.$connect();
    console.log('Database connected (Prisma/PostgreSQL)');
    initialized = true;
    return prisma;
  } catch (error) {
    console.error('Failed to connect to database:', error.message);

    // Fallback: If DATABASE_URL is not set, provide helpful message
    if (!process.env.DATABASE_URL) {
      console.error('\n⚠️  DATABASE_URL environment variable is not set!');
      console.error('   Please create a .env file with your Supabase connection string.');
      console.error('   See .env.example for the required format.\n');
    }
    throw error;
  }
}

async function getDB() {
  if (!initialized) await initDB();
  return prisma;
}

// Graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect();
  await pool.end();
});

module.exports = { initDB, getDB, prisma };
