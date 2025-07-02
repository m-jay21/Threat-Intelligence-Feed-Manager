#!/usr/bin/env node

const path = require('path');
const fs = require('fs');

console.log('=== Threat Intel Manager - Database Diagnostic Tool ===\n');

// Check Node.js version
console.log('Node.js version:', process.version);
console.log('Platform:', process.platform);
console.log('Architecture:', process.arch);
console.log('');

// Check if better-sqlite3 is installed
try {
  const betterSqlite3Path = require.resolve('better-sqlite3');
  console.log('✓ better-sqlite3 found at:', betterSqlite3Path);
  
  // Try to require it
  const Database = require('better-sqlite3');
  console.log('✓ better-sqlite3 module loads successfully');
  
  // Try to create a test database
  const testDbPath = path.join(__dirname, 'test.db');
  const db = new Database(testDbPath);
  console.log('✓ Database connection test successful');
  
  // Clean up test database
  db.close();
  fs.unlinkSync(testDbPath);
  console.log('✓ Test database cleaned up');
  
} catch (error) {
  console.error('✗ better-sqlite3 issue detected:', error.message);
  console.log('');
  console.log('=== Troubleshooting Steps ===');
  console.log('1. Try rebuilding native modules:');
  console.log('   npm rebuild better-sqlite3');
  console.log('');
  console.log('2. If that doesn\'t work, try reinstalling:');
  console.log('   npm uninstall better-sqlite3');
  console.log('   npm install better-sqlite3');
  console.log('');
  console.log('3. On Windows, you might need Visual Studio Build Tools:');
  console.log('   npm install --global --production windows-build-tools');
  console.log('');
  console.log('4. Alternative: Use a different SQLite library:');
  console.log('   npm uninstall better-sqlite3');
  console.log('   npm install sqlite3');
  console.log('');
}

// Check package.json
try {
  const packageJson = require('./package.json');
  console.log('\n=== Package.json Analysis ===');
  console.log('better-sqlite3 version:', packageJson.dependencies['better-sqlite3']);
  console.log('electron version:', packageJson.devDependencies.electron);
  console.log('');
  
  // Check if asarUnpack is configured
  if (packageJson.build && packageJson.build.asarUnpack) {
    console.log('✓ asarUnpack configured for better-sqlite3');
  } else {
    console.log('✗ asarUnpack not configured - this might cause issues in packaged app');
  }
  
} catch (error) {
  console.error('Error reading package.json:', error.message);
}

console.log('\n=== End of Diagnostic ==='); 