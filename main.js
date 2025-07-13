const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const Database = require('better-sqlite3');
const Store = require('electron-store');
const { v4: uuidv4 } = require('uuid');
const CryptoJS = require('crypto-js');
const fs = require('fs');
const https = require('https');
const http = require('http');
const url = require('url');
const zlib = require('zlib');

// Enable hot reload in development
if (process.argv.includes('--dev')) {
  try {
    require('electron-reload')(__dirname, {
      electron: path.join(__dirname, 'node_modules', '.bin', 'electron'),
      hardResetMethod: 'exit'
    });
    console.log('Hot reload enabled for development');
  } catch (error) {
    console.log('Hot reload not available:', error.message);
  }
}

// Initialize electron-store for app settings
const store = new Store({
  encryptionKey: null, // Disable encryption for now
  defaults: {
    settings: {
      downloadInterval: 60,
      logLevel: 'info',
      autoRefresh: true,
      encryptionEnabled: false, // Disable encryption by default
      downloadPath: path.join(app.getPath('userData'), 'downloads'), // Default download path
      lastDownloadTime: null,
      maxLogEntries: 10000 // Maximum number of log entries to keep
    }
  }
});

let mainWindow;
let db;
let downloadScheduler;
let sessionEncryptionKey = null; // In-memory only

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, 'assets/icon.png'), // Add your icon
    titleBarStyle: 'default',
    show: false
  });

  mainWindow.loadFile('index.html');
  logInfo('ui', 'Main window created', { width: 1200, height: 800 });

  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', async () => {
    // Check if encryption is enabled and we need password
    const encryptionEnabled = store.get('settings.encryptionEnabled', false);
    const hasSalt = !!store.get('settings.encryptionSalt');
    
    if (encryptionEnabled && hasSalt && !sessionEncryptionKey) {
      // Show password prompt modal
      mainWindow.webContents.executeJavaScript(`
        document.getElementById('masterPasswordModal').classList.remove('hidden');
        document.body.classList.add('overflow-hidden');
        if (document.getElementById('appMainContent')) {
          document.getElementById('appMainContent').style.filter = 'blur(4px)';
        }
      `);
      logInfo('security', 'Password prompt displayed');
    }
    
    mainWindow.show();
    logInfo('ui', 'Main window displayed');
  });

  // Open DevTools in development
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
    
    // Add keyboard shortcuts for development
    mainWindow.webContents.on('before-input-event', (event, input) => {
      // Ctrl+R to reload
      if (input.control && input.key.toLowerCase() === 'r') {
        mainWindow.reload();
        event.preventDefault();
      }
      // Ctrl+Shift+R to hard reload
      if (input.control && input.shift && input.key.toLowerCase() === 'r') {
        mainWindow.webContents.reloadIgnoringCache();
        event.preventDefault();
      }
      // F12 to toggle DevTools
      if (input.key === 'F12') {
        if (mainWindow.webContents.isDevToolsOpened()) {
          mainWindow.webContents.closeDevTools();
        } else {
          mainWindow.webContents.openDevTools();
        }
        event.preventDefault();
      }
    });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
    // Clear session key when app closes
    sessionEncryptionKey = null;
  });
}

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    try {
      const dbPath = path.join(app.getPath('userData'), 'threatintel.db');
      logInfo('database', 'Initializing database', { path: dbPath });
      
      // Test database connection
      try {
        db = new Database(dbPath);
        logInfo('database', 'Database connection successful');
      } catch (dbError) {
        logError('database', 'Failed to connect to database', { error: dbError.message });
        console.log('This might be a better-sqlite3 native module issue');
        console.log('Trying to provide helpful error information...');
        
        // Check if better-sqlite3 is properly installed
        try {
          const betterSqlite3Path = require.resolve('better-sqlite3');
          console.log('better-sqlite3 found at:', betterSqlite3Path);
        } catch (resolveError) {
          console.error('better-sqlite3 module not found:', resolveError);
        }
        
        reject(new Error(`Database initialization failed: ${dbError.message}. This might be due to native module compilation issues. Try running 'npm rebuild better-sqlite3' or 'npm install' to rebuild native modules.`));
        return;
      }

      // Check if we need to migrate the database
      migrateDatabase();

      // Create tables
      const createTablesSQL = `
        CREATE TABLE IF NOT EXISTS feeds (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT,
          sourceType TEXT NOT NULL,
          dataFormat TEXT NOT NULL,
          apiKey TEXT,
          endpoint TEXT NOT NULL,
          status TEXT DEFAULT 'disabled',
          lastFetched TEXT,
          nextFetch TEXT,
          fetchInterval INTEGER DEFAULT 60,
          createdAt TEXT NOT NULL,
          updatedAt TEXT NOT NULL,
          tags TEXT,
          metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS iocs (
          id TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          type TEXT NOT NULL,
          feedId TEXT NOT NULL,
          tags TEXT,
          dateAdded TEXT NOT NULL,
          confidence INTEGER DEFAULT 50,
          metadata TEXT,
          FOREIGN KEY (feedId) REFERENCES feeds (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS download_logs (
          id TEXT PRIMARY KEY,
          feedId TEXT NOT NULL,
          status TEXT NOT NULL,
          message TEXT,
          timestamp TEXT NOT NULL,
          metadata TEXT,
          FOREIGN KEY (feedId) REFERENCES feeds (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS application_logs (
          id TEXT PRIMARY KEY,
          level TEXT NOT NULL,
          category TEXT NOT NULL,
          message TEXT NOT NULL,
          details TEXT,
          timestamp TEXT NOT NULL,
          userId TEXT DEFAULT 'system',
          sessionId TEXT,
          metadata TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
        CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
        CREATE INDEX IF NOT EXISTS idx_iocs_feedId ON iocs(feedId);
        CREATE INDEX IF NOT EXISTS idx_download_logs_feedId ON download_logs(feedId);
        CREATE INDEX IF NOT EXISTS idx_download_logs_timestamp ON download_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_application_logs_level ON application_logs(level);
        CREATE INDEX IF NOT EXISTS idx_application_logs_category ON application_logs(category);
        CREATE INDEX IF NOT EXISTS idx_application_logs_timestamp ON application_logs(timestamp);
      `;

      db.exec(createTablesSQL);
      logInfo('database', 'Database tables created successfully');
      resolve();
    } catch (error) {
      logError('database', 'Database initialization error', { error: error.message });
      reject(error);
    }
  });
}

// Logging system
let currentSessionId = uuidv4();

function log(level, category, message, details = null, userId = 'system') {
  try {
    const logEntry = {
      id: uuidv4(),
      level: level.toLowerCase(),
      category: category,
      message: message,
      details: details ? JSON.stringify(details) : null,
      timestamp: new Date().toISOString(),
      userId: userId,
      sessionId: currentSessionId,
      metadata: JSON.stringify({
        platform: process.platform,
        version: app.getVersion(),
        arch: process.arch
      })
    };

    // Insert log entry
    const stmt = db.prepare(`
      INSERT INTO application_logs (id, level, category, message, details, timestamp, userId, sessionId, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(logEntry.id, logEntry.level, logEntry.category, logEntry.message, logEntry.details, logEntry.timestamp, logEntry.userId, logEntry.sessionId, logEntry.metadata);

    // Clean up old logs if we exceed the limit
    cleanupOldLogs();

    // Also log to console in development
    if (process.argv.includes('--dev')) {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] [${level.toUpperCase()}] [${category}] ${message}`);
      if (details) {
        console.log('Details:', details);
      }
    }

    return logEntry;
  } catch (error) {
    console.error('Failed to log entry:', error);
  }
}

function cleanupOldLogs() {
  try {
    const maxLogEntries = store.get('settings.maxLogEntries', 10000);
    
    // Get current count
    const countStmt = db.prepare('SELECT COUNT(*) as count FROM application_logs');
    const currentCount = countStmt.get().count;
    
    if (currentCount > maxLogEntries) {
      const excessCount = currentCount - maxLogEntries;
      
      // Delete oldest logs
      const deleteStmt = db.prepare(`
        DELETE FROM application_logs 
        WHERE id IN (
          SELECT id FROM application_logs 
          ORDER BY timestamp ASC 
          LIMIT ?
        )
      `);
      deleteStmt.run(excessCount);
      
      log('info', 'system', `Cleaned up ${excessCount} old log entries`, { previousCount: currentCount, newCount: maxLogEntries });
    }
  } catch (error) {
    console.error('Failed to cleanup old logs:', error);
  }
}

// Convenience logging functions
function logInfo(category, message, details = null) {
  return log('info', category, message, details);
}

function logWarning(category, message, details = null) {
  return log('warning', category, message, details);
}

function logError(category, message, details = null) {
  return log('error', category, message, details);
}

function logDebug(category, message, details = null) {
  return log('debug', category, message, details);
}

// Database migration function
function migrateDatabase() {
  try {
    console.log('Starting database migration check...');
    
    // Check if feeds table exists
    const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='feeds'").get();
    
    if (!tableExists) {
      console.log('Feeds table does not exist, will create with correct schema');
      return;
    }
    
    // Check if feeds table exists and has the correct schema
    const tableInfo = db.prepare("PRAGMA table_info(feeds)").all();
    const columnNames = tableInfo.map(col => col.name);
    
    console.log('Current table columns:', columnNames);
    
    // If the table doesn't exist or is missing the 'status' column, recreate it
    if (!columnNames.includes('status')) {
      console.log('Migrating database schema - status column missing...');
      
      // Drop existing tables if they exist
      db.prepare('DROP TABLE IF EXISTS download_logs').run();
      db.prepare('DROP TABLE IF EXISTS iocs').run();
      db.prepare('DROP TABLE IF EXISTS feeds').run();
      
      console.log('Database tables dropped for migration');
    } else {
      // Check if we need to update foreign key constraints for cascade delete
      console.log('Checking foreign key constraints...');
      
      // Get foreign key information for iocs table
      const iocsForeignKeys = db.prepare("PRAGMA foreign_key_list(iocs)").all();
      const hasCascadeDelete = iocsForeignKeys.some(fk => fk.on_delete === 'CASCADE');
      
      if (!hasCascadeDelete) {
        console.log('Updating foreign key constraints to support cascade delete...');
        
        // Create temporary tables with new schema
        db.prepare(`
          CREATE TABLE iocs_new (
            id TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            type TEXT NOT NULL,
            feedId TEXT NOT NULL,
            tags TEXT,
            dateAdded TEXT NOT NULL,
            confidence INTEGER DEFAULT 50,
            metadata TEXT,
            FOREIGN KEY (feedId) REFERENCES feeds (id) ON DELETE CASCADE
          )
        `).run();
        
        db.prepare(`
          CREATE TABLE download_logs_new (
            id TEXT PRIMARY KEY,
            feedId TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT,
            timestamp TEXT NOT NULL,
            metadata TEXT,
            FOREIGN KEY (feedId) REFERENCES feeds (id) ON DELETE CASCADE
          )
        `).run();
        
        // Copy data from old tables to new tables
        db.prepare('INSERT INTO iocs_new SELECT * FROM iocs').run();
        db.prepare('INSERT INTO download_logs_new SELECT * FROM download_logs').run();
        
        // Drop old tables and rename new ones
        db.prepare('DROP TABLE iocs').run();
        db.prepare('DROP TABLE download_logs').run();
        db.prepare('ALTER TABLE iocs_new RENAME TO iocs').run();
        db.prepare('ALTER TABLE download_logs_new RENAME TO download_logs').run();
        
        // Recreate indexes
        db.prepare('CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)').run();
        db.prepare('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)').run();
        db.prepare('CREATE INDEX IF NOT EXISTS idx_iocs_feedId ON iocs(feedId)').run();
        db.prepare('CREATE INDEX IF NOT EXISTS idx_download_logs_feedId ON download_logs(feedId)').run();
        db.prepare('CREATE INDEX IF NOT EXISTS idx_download_logs_timestamp ON download_logs(timestamp)').run();
        
        console.log('Foreign key constraints updated successfully');
      } else {
        console.log('Foreign key constraints are already up to date');
      }
      
      console.log('Database schema is up to date');
    }
  } catch (err) {
    console.error('Error during database migration:', err);
    // If migration fails, we'll continue with the normal table creation
  }
}

// Generate a random salt (hex string)
function generateSalt(length = 32) {
  const charset = 'abcdef0123456789';
  let salt = '';
  for (let i = 0; i < length; i++) {
    salt += charset[Math.floor(Math.random() * charset.length)];
  }
  return salt;
}

// IPC: Set session encryption key (from renderer after password entry)
ipcMain.handle('set-session-encryption-key', async (event, { password }) => {
  const salt = store.get('settings.encryptionSalt');
  if (!salt) {
    return { success: false, error: 'No salt set' };
  }
  // Derive key using PBKDF2
  try {
    const key = CryptoJS.PBKDF2(password, salt, { keySize: 256/32, iterations: 100000 }).toString();
    sessionEncryptionKey = key;
    return { success: true };
  } catch (err) {
    return { success: false, error: 'Key derivation failed' };
  }
});

// IPC: Clear session encryption key (on app close/lock)
ipcMain.handle('clear-session-encryption-key', async () => {
  sessionEncryptionKey = null;
  return { success: true };
});

// IPC: Check if encryption is enabled and salt is set
ipcMain.handle('encryption-status', async () => {
  return {
    enabled: store.get('settings.encryptionEnabled', false),
    hasSalt: !!store.get('settings.encryptionSalt'),
  };
});

// Update encrypt/decrypt helpers to use sessionEncryptionKey
function decryptApiKey(encryptedApiKey) {
  if (!encryptedApiKey) return null;
  try {
    if (!sessionEncryptionKey) throw new Error('No session encryption key');
    const decrypted = CryptoJS.AES.decrypt(encryptedApiKey, sessionEncryptionKey);
    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.error('Failed to decrypt API key:', error);
    return null;
  }
}

function encryptApiKey(apiKey) {
  if (!apiKey) return null;
  try {
    if (!sessionEncryptionKey) throw new Error('No session encryption key');
    return CryptoJS.AES.encrypt(apiKey, sessionEncryptionKey).toString();
  } catch (error) {
    console.error('Failed to encrypt API key:', error);
    return apiKey;
  }
}

// IPC Handlers for database operations
ipcMain.handle('db-get-feeds', async () => {
  try {
    const rows = db.prepare('SELECT * FROM feeds ORDER BY createdAt DESC').all();
    
    const feeds = rows.map(feed => {
      // Decrypt API key if encryption is enabled
      let decryptedApiKey = feed.apiKey;
      if (store.get('settings.encryptionEnabled') && feed.apiKey) {
        decryptedApiKey = decryptApiKey(feed.apiKey);
      }
      
      return {
        ...feed,
        apiKey: decryptedApiKey,
        tags: feed.tags ? JSON.parse(feed.tags) : [],
        metadata: feed.metadata ? JSON.parse(feed.metadata) : {}
      };
    });
    return feeds;
  } catch (err) {
    console.error('Error getting feeds:', err);
    throw err;
  }
});

ipcMain.handle('db-add-feed', async (event, feedData) => {
  try {
    const id = uuidv4();
    const now = new Date().toISOString();
    
    // Encrypt API key if encryption is enabled
    let encryptedApiKey = feedData.apiKey;
    if (store.get('settings.encryptionEnabled') && feedData.apiKey) {
      encryptedApiKey = encryptApiKey(feedData.apiKey);
    }

    const stmt = db.prepare(`
      INSERT INTO feeds (id, name, description, sourceType, dataFormat, apiKey, endpoint, status, fetchInterval, createdAt, updatedAt, tags, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      feedData.name,
      feedData.description || '',
      feedData.sourceType,
      feedData.dataFormat,
      encryptedApiKey,
      feedData.endpoint,
      feedData.status || 'disabled',
      feedData.fetchInterval || 60,
      now,
      now,
      JSON.stringify(feedData.tags || []),
      JSON.stringify(feedData.metadata || {})
    );

    logInfo('database', 'Feed added successfully', { feedId: id, feedName: feedData.name, sourceType: feedData.sourceType });
    return { success: true, id };
  } catch (err) {
    logError('database', 'Failed to add feed', { error: err.message, feedData });
    console.error('Error adding feed:', err);
    throw err;
  }
});

ipcMain.handle('db-update-feed', async (event, { id, ...feedData }) => {
  try {
    const now = new Date().toISOString();
    
    // Encrypt API key if encryption is enabled
    let encryptedApiKey = feedData.apiKey;
    if (store.get('settings.encryptionEnabled') && feedData.apiKey) {
      encryptedApiKey = encryptApiKey(feedData.apiKey);
    }

    const stmt = db.prepare(`
      UPDATE feeds 
      SET name = ?, description = ?, sourceType = ?, dataFormat = ?, apiKey = ?, endpoint = ?, status = ?, fetchInterval = ?, updatedAt = ?, tags = ?, metadata = ?
      WHERE id = ?
    `);

    stmt.run(
      feedData.name,
      feedData.description || '',
      feedData.sourceType,
      feedData.dataFormat,
      encryptedApiKey,
      feedData.endpoint,
      feedData.status,
      feedData.fetchInterval || 60,
      now,
      JSON.stringify(feedData.tags || []),
      JSON.stringify(feedData.metadata || {}),
      id
    );

    logInfo('database', 'Feed updated successfully', { feedId: id, feedName: feedData.name });
    return { success: true };
  } catch (err) {
    logError('database', 'Failed to update feed', { feedId: id, error: err.message });
    console.error('Error updating feed:', err);
    throw err;
  }
});

ipcMain.handle('db-delete-feed', async (event, id) => {
  try {
    const stmt = db.prepare('DELETE FROM feeds WHERE id = ?');
    stmt.run(id);
    logInfo('database', 'Feed deleted successfully', { feedId: id });
    return { success: true };
  } catch (err) {
    logError('database', 'Failed to delete feed', { feedId: id, error: err.message });
    console.error('Error deleting feed:', err);
    throw err;
  }
});

ipcMain.handle('db-get-settings', async () => {
  return store.get('settings');
});

ipcMain.handle('db-update-settings', async (event, settings) => {
  // Handle encryption key setup
  if (settings.encryptionEnabled && settings.masterPassword) {
    // Use master password as encryption key
    store.set('settings.encryptionKey', settings.masterPassword);
    console.log('Encryption key set from master password');
  } else if (!settings.encryptionEnabled) {
    // Clear encryption key when encryption is disabled
    store.set('settings.encryptionKey', null);
    console.log('Encryption key cleared');
  }
  
  // Remove master password from settings (don't store it)
  const { masterPassword, ...settingsToStore } = settings;
  
  store.set('settings', { ...store.get('settings'), ...settingsToStore });
  return { success: true };
});

// Manual download handlers
ipcMain.handle('manual-download', async () => {
  try {
    logInfo('download', 'Manual download triggered by user');
    await performDailyDownload();
    logInfo('download', 'Manual download completed successfully');
    return { success: true, message: 'Manual download completed' };
  } catch (error) {
    logError('download', 'Manual download failed', { error: error.message });
    console.error('Manual download failed:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('retry-failed-feed', async (event, feedId) => {
  try {
    const feeds = await getEnabledFeeds();
    const feed = feeds.find(f => f.id === feedId);
    
    if (!feed) {
      throw new Error('Feed not found');
    }
    
    await downloadFeed(feed);
    await logDownloadResult(feed.id, 'success', `Retry successful for ${feed.name}`);
    
    return { success: true, message: `Successfully retried ${feed.name}` };
  } catch (error) {
    console.error('Retry failed:', error);
    await logDownloadResult(feedId, 'error', `Retry failed: ${error.message}`);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-download-logs', async () => {
  try {
    const rows = db.prepare(`
      SELECT dl.*, f.name as feedName 
      FROM download_logs dl 
      LEFT JOIN feeds f ON dl.feedId = f.id 
      ORDER BY dl.timestamp DESC 
      LIMIT 100
    `).all();
    
    return rows.map(log => ({
      ...log,
      metadata: log.metadata ? JSON.parse(log.metadata) : {}
    }));
  } catch (err) {
    console.error('Error getting download logs:', err);
    throw err;
  }
});

// IPC: Get download log details
ipcMain.handle('get-download-log-details', async (event, logId) => {
  try {
    const log = db.prepare(`
      SELECT dl.*, f.name as feedName, f.endpoint, f.dataFormat, f.sourceType
      FROM download_logs dl
      LEFT JOIN feeds f ON dl.feedId = f.id
      WHERE dl.id = ?
    `).get(logId);
    
    if (!log) {
      throw new Error('Log not found');
    }
    
    return {
      ...log,
      metadata: log.metadata ? JSON.parse(log.metadata) : {}
    };
  } catch (err) {
    console.error('Error getting download log details:', err);
    throw err;
  }
});

// Get download settings
ipcMain.handle('get-download-settings', async () => {
  return {
    downloadTime: store.get('settings.downloadTime', '04:00'),
    logLevel: store.get('settings.logLevel', 'info'),
    autoRefresh: store.get('settings.autoRefresh', true),
    downloadPath: store.get('settings.downloadPath', path.join(app.getPath('userData'), 'downloads')),
    lastDownloadTime: store.get('settings.lastDownloadTime', null)
  };
});

ipcMain.handle('update-download-path', async (event, newPath) => {
  store.set('settings.downloadPath', newPath);
  return { success: true };
});

// Update download time and restart scheduler
ipcMain.handle('update-download-time', async (event, newTime) => {
  try {
    store.set('settings.downloadTime', newTime);
    updateDownloadScheduler();
    return { success: true };
  } catch (error) {
    console.error('Error updating download time:', error);
    return { success: false, error: error.message };
  }
});

// Pause automatic downloads
ipcMain.handle('pause-download-scheduler', async () => {
  try {
    pauseDownloadScheduler();
    return { success: true };
  } catch (error) {
    console.error('Error pausing download scheduler:', error);
    return { success: false, error: error.message };
  }
});

// Resume automatic downloads
ipcMain.handle('resume-download-scheduler', async () => {
  try {
    resumeDownloadScheduler();
    return { success: true };
  } catch (error) {
    console.error('Error resuming download scheduler:', error);
    return { success: false, error: error.message };
  }
});

// Get scheduler status
ipcMain.handle('get-scheduler-status', async () => {
  try {
    return getSchedulerStatus();
  } catch (error) {
    console.error('Error getting scheduler status:', error);
    return { isRunning: false, downloadTime: '04:00', nextRun: null };
  }
});

ipcMain.handle('get-iocs-count', async () => {
  try {
    const row = db.prepare('SELECT COUNT(*) as count FROM iocs').get();
    return row.count;
  } catch (err) {
    console.error('Error getting IOCs count:', err);
    throw err;
  }
});

// Get feeds count for statistics
ipcMain.handle('get-feeds-count', async () => {
  try {
    const row = db.prepare('SELECT COUNT(*) as count FROM feeds').get();
    return row.count;
  } catch (err) {
    console.error('Error getting feeds count:', err);
    throw err;
  }
});

// Get download logs count for statistics
ipcMain.handle('get-logs-count', async () => {
  try {
    const row = db.prepare('SELECT COUNT(*) as count FROM download_logs').get();
    return row.count;
  } catch (err) {
    console.error('Error getting logs count:', err);
    throw err;
  }
});

ipcMain.handle('clear-download-logs', async () => {
  try {
    db.prepare('DELETE FROM download_logs').run();
    return { success: true };
  } catch (err) {
    console.error('Error clearing download logs:', err);
    throw err;
  }
});

ipcMain.handle('clear-iocs', async () => {
  try {
    db.prepare('DELETE FROM iocs').run();
    return { success: true };
  } catch (err) {
    console.error('Error clearing IOCs:', err);
    throw err;
  }
});

// Get all IOCs with feed information
ipcMain.handle('get-iocs', async () => {
  try {
    const rows = db.prepare(`
      SELECT i.*, f.name as sourceFeed, f.sourceType
      FROM iocs i
      LEFT JOIN feeds f ON i.feedId = f.id
      ORDER BY i.dateAdded DESC
    `).all();
    
    const iocs = rows.map(ioc => {
      const metadata = ioc.metadata ? JSON.parse(ioc.metadata) : {};
      return {
        ...ioc,
        tags: ioc.tags ? JSON.parse(ioc.tags) : [],
        metadata: metadata,
        firstSeen: ioc.dateAdded,
        lastUpdated: ioc.dateAdded,
        threatLevel: metadata.threatLevel || 'medium',
        threatScore: metadata.threatScore || 50,
        threatFactors: metadata.threatFactors || []
      };
    });
    return iocs;
  } catch (err) {
    console.error('Error getting IOCs:', err);
    throw err;
  }
});

// Delete a specific IOC
ipcMain.handle('delete-ioc', async (event, iocId) => {
  try {
    const stmt = db.prepare('DELETE FROM iocs WHERE id = ?');
    stmt.run(iocId);
    return { success: true };
  } catch (err) {
    console.error('Error deleting IOC:', err);
    throw err;
  }
});

// Download scheduler - runs daily at a specific time
function startDownloadScheduler() {
  // Clear any existing scheduler
  if (downloadScheduler) {
    clearInterval(downloadScheduler);
  }
  
  // Get the configured download time (default: 04:00)
  const downloadTime = store.get('settings.downloadTime', '04:00');
  const [hours, minutes] = downloadTime.split(':').map(Number);
  
  // Calculate time until next run
  const now = new Date();
  const nextRun = new Date();
  nextRun.setHours(hours, minutes, 0, 0); // Set to specified time today
  
  // If the time has already passed today, schedule for tomorrow
  if (nextRun <= now) {
    nextRun.setDate(nextRun.getDate() + 1);
  }
  
  const timeUntilNextRun = nextRun.getTime() - now.getTime();
  
  // Schedule the first run
  downloadScheduler = setTimeout(async () => {
    console.log(`Starting scheduled daily download at ${downloadTime}...`);
    await performDailyDownload();
    
    // After the first run, schedule subsequent daily runs
    scheduleDailyRuns(downloadTime);
  }, timeUntilNextRun);
  
  console.log(`Download scheduler started - will run daily at ${downloadTime}`);
  console.log(`Next scheduled download: ${nextRun.toLocaleString()}`);
}

// Schedule daily runs at the specified time
function scheduleDailyRuns(downloadTime) {
  const [hours, minutes] = downloadTime.split(':').map(Number);
  const dailyInterval = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  
  downloadScheduler = setInterval(async () => {
    console.log(`Starting scheduled daily download at ${downloadTime}...`);
    await performDailyDownload();
  }, dailyInterval);
}

// Update download scheduler with new time
function updateDownloadScheduler() {
  console.log('Updating download scheduler with new time...');
  startDownloadScheduler();
}

// Update download scheduler with new interval
function updateDownloadScheduler() {
  console.log('Updating download scheduler with new interval...');
  startDownloadScheduler();
}

// Pause automatic downloads
function pauseDownloadScheduler() {
  if (downloadScheduler) {
    clearInterval(downloadScheduler);
    downloadScheduler = null;
    console.log('Download scheduler paused');
  }
}

// Resume automatic downloads
function resumeDownloadScheduler() {
  if (!downloadScheduler) {
    startDownloadScheduler();
    console.log('Download scheduler resumed');
  }
}

// Get scheduler status
function getSchedulerStatus() {
  const downloadTime = store.get('settings.downloadTime', '04:00');
  const isRunning = !!downloadScheduler;
  
  // Calculate next run time
  let nextRun = null;
  if (isRunning) {
    const [hours, minutes] = downloadTime.split(':').map(Number);
    const now = new Date();
    const nextRunDate = new Date();
    nextRunDate.setHours(hours, minutes, 0, 0);
    
    // If the time has already passed today, it's tomorrow
    if (nextRunDate <= now) {
      nextRunDate.setDate(nextRunDate.getDate() + 1);
    }
    
    nextRun = nextRunDate.toISOString();
  }
  
  return {
    isRunning,
    downloadTime,
    nextRun
  };
}

// Perform daily download cycle
async function performDailyDownload() {
  try {
    console.log('Starting daily download cycle...');
    
    // Clear IOC table
    await clearIOCDatabase();
    
    // Get all enabled feeds
    const feeds = await getEnabledFeeds();
    
    if (feeds.length === 0) {
      console.log('No enabled feeds found for download');
      return;
    }
    
    // Download from each feed
    for (const feed of feeds) {
      try {
        await downloadFeed(feed);
        await logDownloadResult(feed.id, 'success', `Downloaded ${feed.name} successfully`);
      } catch (error) {
        console.error(`Failed to download feed ${feed.name}:`, error);
        await logDownloadResult(feed.id, 'error', `Failed to download: ${error.message}`);
        
        // Notify user of failure
        if (mainWindow) {
          mainWindow.webContents.send('feed-download-failed', {
            feedId: feed.id,
            feedName: feed.name,
            error: error.message
          });
        }
      }
    }
    
    // Update last download time
    store.set('settings.lastDownloadTime', new Date().toISOString());
    
    console.log('Daily download cycle completed');
    
  } catch (error) {
    console.error('Error in daily download cycle:', error);
  }
}

// Clear IOC database
async function clearIOCDatabase() {
  try {
    db.prepare('DELETE FROM iocs').run();
    console.log('IOC database cleared');
  } catch (err) {
    console.error('Error clearing IOC database:', err);
    throw err;
  }
}

// Get enabled feeds
async function getEnabledFeeds() {
  try {
    console.log('Getting enabled feeds...');
    console.log('Current database file:', db.name);
    
    // First check if the table exists
    const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='feeds'").get();
    if (!tableExists) {
      console.log('Feeds table does not exist, returning empty array');
      return [];
    }
    
    // Check table schema
    const tableInfo = db.prepare("PRAGMA table_info(feeds)").all();
    const columnNames = tableInfo.map(col => col.name);
    console.log('Feeds table columns:', columnNames);
    
    console.log('Executing query: SELECT * FROM feeds WHERE status = "enabled"');
    let rows = [];
    try {
      // First try a simple query to test the table
      console.log('Testing simple query: SELECT COUNT(*) FROM feeds');
      const countResult = db.prepare('SELECT COUNT(*) as count FROM feeds').get();
      console.log('Total feeds in table:', countResult.count);
      
      // Check what status values exist in the table
      console.log('Checking all status values in the table:');
      const statusValues = db.prepare('SELECT DISTINCT status FROM feeds').all();
      console.log('Status values found:', statusValues);
      
      // Show all feeds and their status
      console.log('All feeds in table:');
      const allFeeds = db.prepare('SELECT id, name, status FROM feeds').all();
      allFeeds.forEach(feed => {
        console.log(`  - ${feed.name}: status = "${feed.status}"`);
      });
      
      // Now try the actual query with different syntax
      console.log('Trying query with single quotes: SELECT * FROM feeds WHERE status = \'enabled\'');
      rows = db.prepare("SELECT * FROM feeds WHERE status = 'enabled'").all();
      console.log(`Found ${rows.length} enabled feeds with single quotes`);
      
      if (rows.length === 0) {
        console.log('Trying query with parameterized statement');
        const stmt = db.prepare('SELECT * FROM feeds WHERE status = ?');
        rows = stmt.all('enabled');
        console.log(`Found ${rows.length} enabled feeds with parameterized query`);
      }
    } catch (queryError) {
      console.error('Query failed with error:', queryError);
      console.error('Query error details:', {
        message: queryError.message,
        code: queryError.code,
        stack: queryError.stack
      });
      throw queryError;
    }
    
    const feeds = rows.map(feed => {
      // Decrypt API key if encryption is enabled
      let decryptedApiKey = feed.apiKey;
      if (store.get('settings.encryptionEnabled') && feed.apiKey) {
        decryptedApiKey = decryptApiKey(feed.apiKey);
      }
      
      return {
        ...feed,
        apiKey: decryptedApiKey,
        tags: feed.tags ? JSON.parse(feed.tags) : [],
        metadata: feed.metadata ? JSON.parse(feed.metadata) : {}
      };
    });
    return feeds;
  } catch (err) {
    console.error('Error getting enabled feeds:', err);
    throw err;
  }
}

// Download from a specific feed
async function downloadFeed(feed) {
  return new Promise((resolve, reject) => {
    let downloadPath = store.get('settings.downloadPath');
    
    logInfo('download', `Starting download for feed: ${feed.name}`, { feedId: feed.id, endpoint: feed.endpoint });
    
    // Debug logging
    console.log('Current download path from store:', downloadPath);
    
    // Fallback to default path if not set
    if (!downloadPath) {
      downloadPath = path.join(app.getPath('userData'), 'downloads');
      store.set('settings.downloadPath', downloadPath);
      logInfo('download', 'Set default download path', { path: downloadPath });
    }
    
    // Ensure download directory exists
    if (!fs.existsSync(downloadPath)) {
      fs.mkdirSync(downloadPath, { recursive: true });
      logInfo('download', 'Created download directory', { path: downloadPath });
    }
    
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const feedFolder = path.join(downloadPath, feed.name.replace(/[^a-zA-Z0-9]/g, '_'));
    const filePath = path.join(feedFolder, `${today}.txt`);
    
    console.log('Feed folder:', feedFolder);
    console.log('File path:', filePath);
    
    // Create feed folder if it doesn't exist
    if (!fs.existsSync(feedFolder)) {
      fs.mkdirSync(feedFolder, { recursive: true });
    }
    
    // Function to make HTTP request with redirect support
    function makeRequest(urlString, maxRedirects = 5) {
      if (maxRedirects <= 0) {
        reject(new Error('Too many redirects'));
        return;
      }
      
      // Determine protocol and make request
      const parsedUrl = url.parse(urlString);
      const client = parsedUrl.protocol === 'https:' ? https : http;
      
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.path,
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Accept': 'application/json, text/plain, */*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'keep-alive',
          'Cache-Control': 'no-cache'
        }
      };
      
      // Add API key if provided
      if (feed.apiKey) {
        options.headers['Authorization'] = `Bearer ${feed.apiKey}`;
      }
      
      const req = client.request(options, (res) => {
        let data = '';
        
        // Check if response is compressed
        const contentEncoding = res.headers['content-encoding'];
        const contentType = res.headers['content-type'];
        
        console.log(`Response status: ${res.statusCode}`);
        console.log(`Content-Type: ${contentType}`);
        console.log(`Content-Encoding: ${contentEncoding}`);
        
        // Handle redirects
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          console.log(`Following redirect to: ${res.headers.location}`);
          makeRequest(res.headers.location, maxRedirects - 1);
          return;
        }
        
        // Handle different response types
        let responseStream = res;
        
        if (contentEncoding === 'gzip') {
          responseStream = res.pipe(zlib.createGunzip());
        } else if (contentEncoding === 'deflate') {
          responseStream = res.pipe(zlib.createInflate());
        } else if (contentType && contentType.includes('application/zip')) {
          // For ZIP files, we'll need to handle them differently
          console.log('ZIP file detected - will need special handling');
        }
        
        responseStream.on('data', (chunk) => {
          data += chunk;
        });
        
        responseStream.on('end', async () => {
          try {
            // Debug: Log the first 200 characters of the response
            console.log(`Response from ${feed.name}:`, data.substring(0, 200));
            
            // Check if we got a ZIP file (which we can't handle yet)
            if (contentType && contentType.includes('application/zip')) {
              throw new Error('ZIP file response not supported yet. Try a different feed URL.');
            }
            
            // Special case for test feed
            if (feed.name.toLowerCase().includes('test')) {
              console.log('Using test data for test feed');
              data = JSON.stringify({
                iocs: [
                  { value: "192.168.1.1", type: "ip" },
                  { value: "malware.example.com", type: "domain" },
                  { value: "https://evil.com/malware.exe", type: "url" },
                  { value: "a1b2c3d4e5f678901234567890123456", type: "hash" }
                ]
              });
            }
            
            // Parse and extract IOCs first
            const iocs = await parseIOCs(data, feed.dataFormat, feed.id);
            
            // Create clean text content with just IOC values
            const cleanTextContent = iocs.map(ioc => ioc.value).join('\n');
            
            // Save clean text data to file (instead of raw JSON)
            fs.writeFileSync(filePath, cleanTextContent);
            
            // Store IOCs in database
            await storeIOCs(iocs);
            
            // Update feed last fetched time
            await updateFeedLastFetched(feed.id);
            
            logInfo('download', `Successfully downloaded feed: ${feed.name}`, { feedId: feed.id, iocCount: iocs.length });
            resolve();
            
          } catch (error) {
            logError('download', `Failed to process feed: ${feed.name}`, { feedId: feed.id, error: error.message });
            reject(error);
          }
        });
        
        responseStream.on('error', (error) => {
          reject(error);
        });
      });
      
      req.on('error', (error) => {
        reject(error);
      });
      
      req.end();
    }
    
    // Start the request
    makeRequest(feed.endpoint);
  });
}

// Parse IOCs from downloaded data
async function parseIOCs(data, format, feedId) {
  const iocs = [];
  
  try {
    let parsedData;
    
    switch (format.toUpperCase()) {
      case 'JSON':
        parsedData = JSON.parse(data);
        iocs.push(...extractIOCsFromJSON(parsedData, feedId));
        break;
        
      case 'CSV':
        iocs.push(...extractIOCsFromCSV(data, feedId));
        break;
        
      case 'XML':
        iocs.push(...extractIOCsFromXML(data, feedId));
        break;
        
      case 'TEXT':
        iocs.push(...extractIOCsFromText(data, feedId));
        break;
        
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
    
  } catch (error) {
    console.error('Error parsing IOCs:', error);
    throw error;
  }
  
  return iocs;
}

// Extract IOCs from JSON data
function extractIOCsFromJSON(data, feedId) {
  const iocs = [];
  const jsonString = JSON.stringify(data);
  
  // Get feed information for threat level calculation
  const feed = db.prepare('SELECT * FROM feeds WHERE id = ?').get(feedId);
  
  // Extract IPs, domains, URLs, hashes, emails
  const patterns = {
    ip: /(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)/g,
    domain: /(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)/g,
    url: /(?:https?:\/\/[^\s]+)/g,
    hash: /(?:\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b)/g, // MD5, SHA1, SHA256
    email: /(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)/g
  };
  
  for (const [type, pattern] of Object.entries(patterns)) {
    const matches = jsonString.match(pattern);
    if (matches) {
      for (const match of matches) {
        // Create base IOC
        const baseIOC = {
          id: uuidv4(),
          value: match,
          type: type,
          feedId: feedId,
          dateAdded: new Date().toISOString(),
          confidence: 50,
          tags: [],
          metadata: {}
        };
        
        // Determine threat level
        const threatAnalysis = determineThreatLevel(baseIOC, feed, baseIOC.metadata);
        
        // Update IOC with threat level information
        const ioc = {
          ...baseIOC,
          metadata: threatAnalysis.metadata
        };
        
        iocs.push(ioc);
      }
    }
  }
  
  return iocs;
}

// Extract IOCs from CSV data
function extractIOCsFromCSV(data, feedId) {
  const iocs = [];
  const lines = data.split('\n');
  
  // Get feed information for threat level calculation
  const feed = db.prepare('SELECT * FROM feeds WHERE id = ?').get(feedId);
  
  for (const line of lines) {
    const columns = line.split(',').map(col => col.trim().replace(/"/g, ''));
    
    for (const column of columns) {
      // Check each column for IOC patterns
      const patterns = {
        ip: /(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)/g,
        domain: /(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)/g,
        url: /(?:https?:\/\/[^\s]+)/g,
        hash: /(?:\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b)/g,
        email: /(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)/g
      };
      
      for (const [type, pattern] of Object.entries(patterns)) {
        const matches = column.match(pattern);
        if (matches) {
          for (const match of matches) {
            // Create base IOC
            const baseIOC = {
              id: uuidv4(),
              value: match,
              type: type,
              feedId: feedId,
              dateAdded: new Date().toISOString(),
              confidence: 50,
              tags: [],
              metadata: {}
            };
            
            // Determine threat level
            const threatAnalysis = determineThreatLevel(baseIOC, feed, baseIOC.metadata);
            
            // Update IOC with threat level information
            const ioc = {
              ...baseIOC,
              metadata: threatAnalysis.metadata
            };
            
            iocs.push(ioc);
          }
        }
      }
    }
  }
  
  return iocs;
}

// Extract IOCs from XML data
function extractIOCsFromXML(data, feedId) {
  // For now, treat XML as text and extract patterns
  return extractIOCsFromText(data, feedId);
}

// Extract IOCs from text data
function extractIOCsFromText(data, feedId) {
  const iocs = [];
  
  // Get feed information for threat level calculation
  const feed = db.prepare('SELECT * FROM feeds WHERE id = ?').get(feedId);
  
  const patterns = {
    ip: /(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)/g,
    domain: /(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)/g,
    url: /(?:https?:\/\/[^\s]+)/g,
    hash: /(?:\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b)/g,
    email: /(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)/g
  };
  
  for (const [type, pattern] of Object.entries(patterns)) {
    const matches = data.match(pattern);
    if (matches) {
      for (const match of matches) {
        // Create base IOC
        const baseIOC = {
          id: uuidv4(),
          value: match,
          type: type,
          feedId: feedId,
          dateAdded: new Date().toISOString(),
          confidence: 50,
          tags: [],
          metadata: {}
        };
        
        // Determine threat level
        const threatAnalysis = determineThreatLevel(baseIOC, feed, baseIOC.metadata);
        
        // Update IOC with threat level information
        const ioc = {
          ...baseIOC,
          metadata: threatAnalysis.metadata
        };
        
        iocs.push(ioc);
      }
    }
  }
  
  return iocs;
}

// Store IOCs in database
async function storeIOCs(iocs) {
  try {
    if (iocs.length === 0) {
      return;
    }
    
    const stmt = db.prepare(`
      INSERT INTO iocs (id, value, type, feedId, dateAdded, confidence, tags, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    for (const ioc of iocs) {
      stmt.run(
        ioc.id,
        ioc.value,
        ioc.type,
        ioc.feedId,
        ioc.dateAdded,
        ioc.confidence,
        JSON.stringify(ioc.tags),
        JSON.stringify(ioc.metadata)
      );
    }
  } catch (err) {
    console.error('Error storing IOCs:', err);
    throw err;
  }
}

// Update feed last fetched time
async function updateFeedLastFetched(feedId) {
  try {
    const stmt = db.prepare('UPDATE feeds SET lastFetched = ? WHERE id = ?');
    stmt.run(new Date().toISOString(), feedId);
  } catch (err) {
    console.error('Error updating feed last fetched time:', err);
    throw err;
  }
}

// Log download result
async function logDownloadResult(feedId, status, message) {
  try {
    const stmt = db.prepare(`
      INSERT INTO download_logs (id, feedId, status, message, timestamp, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      uuidv4(),
      feedId,
      status,
      message,
      new Date().toISOString(),
      JSON.stringify({})
    );
  } catch (err) {
    console.error('Error logging download result:', err);
    throw err;
  }
}

// Select directory dialog
ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Download Directory'
  });
  
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});

// Export feeds to JSON file
ipcMain.handle('export-feeds', async () => {
  try {
    const feeds = await getFeeds();
    const exportData = {
      feeds: feeds,
      exportDate: new Date().toISOString(),
      version: '1.0'
    };
    
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Feeds',
      defaultPath: `feeds-export-${new Date().toISOString().split('T')[0]}.json`,
      filters: [
        { name: 'JSON Files', extensions: ['json'] }
      ]
    });
    
    if (!result.canceled && result.filePath) {
      fs.writeFileSync(result.filePath, JSON.stringify(exportData, null, 2));
      return { success: true, filePath: result.filePath };
    }
    return { success: false, message: 'Export cancelled' };
  } catch (error) {
    console.error('Error exporting feeds:', error);
    throw error;
  }
});

// Export IOCs to JSON file
ipcMain.handle('export-iocs', async () => {
  try {
    const iocs = await getIOCs();
    const exportData = {
      iocs: iocs,
      exportDate: new Date().toISOString(),
      version: '1.0'
    };
    
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export IOCs',
      defaultPath: `iocs-export-${new Date().toISOString().split('T')[0]}.json`,
      filters: [
        { name: 'JSON Files', extensions: ['json'] },
        { name: 'CSV Files', extensions: ['csv'] }
      ]
    });
    
    if (!result.canceled && result.filePath) {
      if (result.filePath.endsWith('.csv')) {
        // Export as CSV
        const csvContent = convertIOCsToCSV(iocs);
        fs.writeFileSync(result.filePath, csvContent);
      } else {
        // Export as JSON
        fs.writeFileSync(result.filePath, JSON.stringify(exportData, null, 2));
      }
      return { success: true, filePath: result.filePath };
    }
    return { success: false, message: 'Export cancelled' };
  } catch (error) {
    console.error('Error exporting IOCs:', error);
    throw error;
  }
});

// Wipe all data
ipcMain.handle('wipe-all-data', async () => {
  try {
    // Clear all tables
    await clearAllTables();
    
    // Clear settings
    store.clear();
    
    // Reset to default settings
    store.set('settings', {
      downloadInterval: 60,
      logLevel: 'info',
      autoRefresh: true,
      encryptionEnabled: false,
      downloadPath: path.join(app.getPath('userData'), 'downloads'),
      lastDownloadTime: null
    });
    
    return { success: true };
  } catch (error) {
    console.error('Error wiping all data:', error);
    throw error;
  }
});

// Helper function to convert IOCs to CSV
function convertIOCsToCSV(iocs) {
  const headers = ['Value', 'Type', 'Source Feed', 'Threat Level', 'First Seen', 'Last Updated', 'Tags'];
  const rows = iocs.map(ioc => [
    ioc.value,
    ioc.type,
    ioc.sourceFeed || '',
    ioc.threatLevel || 'medium',
    ioc.firstSeen,
    ioc.lastUpdated,
    (ioc.tags || []).join(', ')
  ]);
  
  return [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
}

// Helper function to clear all tables
async function clearAllTables() {
  try {
    db.prepare('DELETE FROM iocs').run();
    db.prepare('DELETE FROM download_logs').run();
    db.prepare('DELETE FROM feeds').run();
  } catch (err) {
    console.error('Error clearing all tables:', err);
    throw err;
  }
}

// Get all feeds
async function getFeeds() {
  try {
    const rows = db.prepare('SELECT * FROM feeds ORDER BY createdAt DESC').all();
    
    const feeds = rows.map(feed => {
      // Decrypt API key if encryption is enabled
      let decryptedApiKey = feed.apiKey;
      if (store.get('settings.encryptionEnabled') && feed.apiKey) {
        decryptedApiKey = decryptApiKey(feed.apiKey);
      }
      
      return {
        ...feed,
        apiKey: decryptedApiKey,
        tags: feed.tags ? JSON.parse(feed.tags) : [],
        metadata: feed.metadata ? JSON.parse(feed.metadata) : {}
      };
    });
    return feeds;
  } catch (err) {
    console.error('Error getting feeds:', err);
    throw err;
  }
}

// Get all IOCs with feed information
async function getIOCs() {
  try {
    const rows = db.prepare(`
      SELECT i.*, f.name as sourceFeed, f.sourceType
      FROM iocs i
      LEFT JOIN feeds f ON i.feedId = f.id
      ORDER BY i.dateAdded DESC
    `).all();
    
    const iocs = rows.map(ioc => {
      const metadata = ioc.metadata ? JSON.parse(ioc.metadata) : {};
      return {
        ...ioc,
        tags: ioc.tags ? JSON.parse(ioc.tags) : [],
        metadata: metadata,
        firstSeen: ioc.dateAdded,
        lastUpdated: ioc.dateAdded,
        threatLevel: metadata.threatLevel || 'medium',
        threatScore: metadata.threatScore || 50,
        threatFactors: metadata.threatFactors || []
      };
    });
    return iocs;
  } catch (err) {
    console.error('Error getting IOCs:', err);
    throw err;
  }
}

// IPC: Setup encryption (initial setup)
ipcMain.handle('setup-encryption', async (event, { masterPassword }) => {
  try {
    // Generate a new salt
    const salt = generateSalt();
    
    // Derive key using PBKDF2
    const key = CryptoJS.PBKDF2(masterPassword, salt, { keySize: 256/32, iterations: 100000 }).toString();
    
    // Store the salt
    store.set('settings.encryptionSalt', salt);
    store.set('settings.encryptionEnabled', true);
    
    // Get all existing feeds and encrypt their API keys
    const feeds = await getFeeds();
    for (const feed of feeds) {
      if (feed.apiKey && !feed.apiKey.startsWith('encrypted:')) {
        // Encrypt the API key
        const encryptedApiKey = CryptoJS.AES.encrypt(feed.apiKey, key).toString();
        
        // Update the feed with encrypted API key using direct database operation
        const now = new Date().toISOString();
        const stmt = db.prepare(`
          UPDATE feeds 
          SET apiKey = ?, updatedAt = ?
          WHERE id = ?
        `);
        
        stmt.run(encryptedApiKey, now, feed.id);
      }
    }
    
    // Set session key for current session
    sessionEncryptionKey = key;
    
    return { success: true };
  } catch (error) {
    console.error('Error setting up encryption:', error);
    return { success: false, error: error.message };
  }
});

// IPC: Disable encryption (decrypt all API keys)
ipcMain.handle('disable-encryption', async (event) => {
  try {
    // Get all feeds and decrypt their API keys
    const feeds = await getFeeds();
    for (const feed of feeds) {
      if (feed.apiKey && feed.apiKey.startsWith('encrypted:')) {
        // Decrypt the API key using current session key
        if (sessionEncryptionKey) {
          const encryptedApiKey = feed.apiKey.replace('encrypted:', '');
          const decryptedApiKey = CryptoJS.AES.decrypt(encryptedApiKey, sessionEncryptionKey).toString(CryptoJS.enc.Utf8);
          
          // Update the feed with decrypted API key using direct database operation
          const now = new Date().toISOString();
          const stmt = db.prepare(`
            UPDATE feeds 
            SET apiKey = ?, updatedAt = ?
            WHERE id = ?
          `);
          
          stmt.run(decryptedApiKey, now, feed.id);
        }
      }
    }
    
    // Clear encryption settings
    store.delete('settings.encryptionSalt');
    store.set('settings.encryptionEnabled', false);
    
    // Clear session key
    sessionEncryptionKey = null;
    
    return { success: true };
  } catch (error) {
    console.error('Error disabling encryption:', error);
    return { success: false, error: error.message };
  }
});

// Threat level determination function
function determineThreatLevel(ioc, feed, metadata = {}) {
  let score = 0;
  const factors = [];
  
  // Factor 1: IOC Type (different types have different inherent risk)
  const typeScores = {
    'hash': 30,      // Malware hashes are high risk
    'ip': 25,        // IP addresses can be high risk
    'domain': 20,    // Domains can be medium-high risk
    'url': 15,       // URLs can be medium risk
    'email': 10      // Emails are typically lower risk
  };
  score += typeScores[ioc.type] || 15;
  factors.push(`Type (${ioc.type}): +${typeScores[ioc.type] || 15}`);
  
  // Factor 2: Feed Reputation (some feeds are more reliable/important)
  const feedReputation = getFeedReputation(feed);
  score += feedReputation.score;
  factors.push(`Feed Reputation (${feed.name}): +${feedReputation.score}`);
  
  // Factor 3: IOC Value Analysis
  const valueScore = analyzeIOCValue(ioc.value, ioc.type);
  score += valueScore.score;
  factors.push(`Value Analysis: +${valueScore.score}`);
  
  // Factor 4: Confidence Score
  const confidence = metadata.confidence || 50;
  const confidenceScore = Math.floor(confidence / 10); // 0-10 points based on confidence
  score += confidenceScore;
  factors.push(`Confidence (${confidence}%): +${confidenceScore}`);
  
  // Factor 5: Recent Activity (newer IOCs might be more relevant)
  const recencyScore = calculateRecencyScore(metadata.firstSeen || new Date().toISOString());
  score += recencyScore;
  factors.push(`Recency: +${recencyScore}`);
  
  // Factor 6: Tags Analysis
  const tagScore = analyzeTags(metadata.tags || []);
  score += tagScore;
  factors.push(`Tags: +${tagScore}`);
  
  // Determine threat level based on total score
  let threatLevel;
  if (score >= 80) {
    threatLevel = 'high';
  } else if (score >= 50) {
    threatLevel = 'medium';
  } else {
    threatLevel = 'low';
  }
  
  return {
    threatLevel,
    score,
    factors,
    metadata: {
      ...metadata,
      threatScore: score,
      threatFactors: factors,
      threatLevel
    }
  };
}

// Get feed reputation score
function getFeedReputation(feed) {
  // Known high-reputation feeds
  const highReputationFeeds = [
    'alienvault', 'otx', 'abuse', 'virustotal', 'threatfox', 'malwarebazaar',
    'phishtank', 'urlhaus', 'malware-traffic-analysis', 'emergingthreats'
  ];
  
  // Known medium-reputation feeds
  const mediumReputationFeeds = [
    'openphish', 'phishtank', 'urlhaus', 'malware-traffic-analysis'
  ];
  
  const feedName = feed.name.toLowerCase();
  
  if (highReputationFeeds.some(name => feedName.includes(name))) {
    return { score: 25, reason: 'High reputation feed' };
  } else if (mediumReputationFeeds.some(name => feedName.includes(name))) {
    return { score: 15, reason: 'Medium reputation feed' };
  } else if (feed.sourceType === 'API') {
    return { score: 10, reason: 'API feed' };
  } else {
    return { score: 5, reason: 'Standard feed' };
  }
}

// Analyze IOC value for suspicious patterns
function analyzeIOCValue(value, type) {
  let score = 0;
  
  switch (type) {
    case 'ip':
      // Check for known malicious IP ranges
      if (isPrivateIP(value)) {
        score += 5; // Private IPs are less likely to be malicious
      } else if (isKnownMaliciousIP(value)) {
        score += 20; // Known malicious IPs
      } else if (isSuspiciousIP(value)) {
        score += 10; // Suspicious patterns
      }
      break;
      
    case 'domain':
      // Check for suspicious domain patterns
      if (isSuspiciousDomain(value)) {
        score += 15;
      } else if (isNewDomain(value)) {
        score += 10; // New domains might be suspicious
      }
      break;
      
    case 'url':
      // Check for suspicious URL patterns
      if (isSuspiciousURL(value)) {
        score += 15;
      }
      break;
      
    case 'hash':
      // All hashes are potentially high risk
      score += 10;
      break;
      
    case 'email':
      // Check for suspicious email patterns
      if (isSuspiciousEmail(value)) {
        score += 10;
      }
      break;
  }
  
  return { score };
}

// Helper functions for IOC analysis
function isPrivateIP(ip) {
  const privateRanges = [
    /^10\./,           // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
    /^192\.168\./      // 192.168.0.0/16
  ];
  return privateRanges.some(range => range.test(ip));
}

function isKnownMaliciousIP(ip) {
  // This would typically connect to a threat intelligence API
  // For now, we'll use some known patterns
  const suspiciousPatterns = [
    /^185\./,  // Some known malicious ranges
    /^91\.194\./,
    /^45\.95\./
  ];
  return suspiciousPatterns.some(pattern => pattern.test(ip));
}

function isSuspiciousIP(ip) {
  // Check for patterns that might indicate suspicious activity
  const suspiciousPatterns = [
    /\.(tk|ml|ga|cf|gq)$/, // Free TLDs often used for malicious purposes
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.1$/, // Often used for C2 servers
  ];
  return suspiciousPatterns.some(pattern => pattern.test(ip));
}

function isSuspiciousDomain(domain) {
  const suspiciousPatterns = [
    /\.(tk|ml|ga|cf|gq)$/, // Free TLDs
    /^[a-z0-9]{16,}\./,    // Very long random subdomains
    /^[0-9a-f]{8,}\./,     // Hex-like subdomains
    /(malware|virus|hack|exploit|crack)/i // Suspicious keywords
  ];
  return suspiciousPatterns.some(pattern => pattern.test(domain));
}

function isNewDomain(domain) {
  // This would typically check against a domain age database
  // For now, we'll assume domains with certain patterns are newer
  const newDomainPatterns = [
    /^[a-z0-9]{8,}\./,     // Random-looking subdomains
    /^[0-9]{8,}\./         // Numeric subdomains
  ];
  return newDomainPatterns.some(pattern => pattern.test(domain));
}

function isSuspiciousURL(url) {
  const suspiciousPatterns = [
    /\.(tk|ml|ga|cf|gq)\//, // Free TLDs
    /\/[a-z0-9]{16,}\//,    // Very long random paths
    /(malware|virus|hack|exploit|crack)/i, // Suspicious keywords
    /\.(exe|bat|cmd|scr|pif|com)$/i // Executable files
  ];
  return suspiciousPatterns.some(pattern => pattern.test(url));
}

function isSuspiciousEmail(email) {
  const suspiciousPatterns = [
    /^[a-z0-9]{16,}@/,     // Very long random usernames
    /@[a-z0-9]{16,}\./,    // Very long random domains
    /(admin|support|security|update|alert)@[a-z0-9]{8,}\./i // Common phishing patterns
  ];
  return suspiciousPatterns.some(pattern => pattern.test(email));
}

// Calculate recency score (newer IOCs get higher scores)
function calculateRecencyScore(firstSeen) {
  const now = new Date();
  const seen = new Date(firstSeen);
  const daysDiff = (now - seen) / (1000 * 60 * 60 * 24);
  
  if (daysDiff <= 1) return 10;      // Last 24 hours
  if (daysDiff <= 7) return 8;       // Last week
  if (daysDiff <= 30) return 5;      // Last month
  if (daysDiff <= 90) return 3;      // Last 3 months
  return 1;                          // Older
}

// Analyze tags for threat indicators
function analyzeTags(tags) {
  let score = 0;
  const highThreatTags = ['malware', 'ransomware', 'trojan', 'backdoor', 'c2', 'botnet'];
  const mediumThreatTags = ['phishing', 'spam', 'suspicious', 'malicious'];
  
  tags.forEach(tag => {
    if (highThreatTags.includes(tag.toLowerCase())) {
      score += 10;
    } else if (mediumThreatTags.includes(tag.toLowerCase())) {
      score += 5;
    }
  });
  
  return score;
}

// Add IPC handlers for logs functionality
ipcMain.handle('get-application-logs', async (event, filters = {}) => {
  try {
    let query = `
      SELECT id, level, category, message, details, timestamp, userId, sessionId, metadata
      FROM application_logs
      WHERE 1=1
    `;
    const params = [];

    // Apply filters
    if (filters.level && filters.level !== 'all') {
      query += ' AND level = ?';
      params.push(filters.level);
    }

    if (filters.category && filters.category !== 'all') {
      query += ' AND category = ?';
      params.push(filters.category);
    }

    if (filters.search) {
      query += ' AND (message LIKE ? OR details LIKE ?)';
      const searchTerm = `%${filters.search}%`;
      params.push(searchTerm, searchTerm);
    }

    if (filters.startDate) {
      query += ' AND timestamp >= ?';
      params.push(filters.startDate);
    }

    if (filters.endDate) {
      query += ' AND timestamp <= ?';
      params.push(filters.endDate);
    }

    // Add ordering and pagination
    query += ' ORDER BY timestamp DESC';
    
    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
    } else {
      query += ' LIMIT 1000'; // Default limit
    }

    const stmt = db.prepare(query);
    const logs = stmt.all(...params);

    // Parse JSON fields
    logs.forEach(log => {
      if (log.details) {
        try {
          log.details = JSON.parse(log.details);
        } catch (e) {
          // Keep as string if parsing fails
        }
      }
      if (log.metadata) {
        try {
          log.metadata = JSON.parse(log.metadata);
        } catch (e) {
          // Keep as string if parsing fails
        }
      }
    });

    return { success: true, logs };
  } catch (error) {
    logError('database', 'Failed to retrieve application logs', { error: error.message });
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-log-statistics', async () => {
  try {
    const stats = {};
    
    // Total logs
    const totalStmt = db.prepare('SELECT COUNT(*) as count FROM application_logs');
    stats.total = totalStmt.get().count;
    
    // Logs by level
    const levelStmt = db.prepare(`
      SELECT level, COUNT(*) as count 
      FROM application_logs 
      GROUP BY level
    `);
    stats.byLevel = levelStmt.all();
    
    // Logs by category
    const categoryStmt = db.prepare(`
      SELECT category, COUNT(*) as count 
      FROM application_logs 
      GROUP BY category
      ORDER BY count DESC
      LIMIT 10
    `);
    stats.byCategory = categoryStmt.all();
    
    // Recent activity (last 24 hours)
    const recentStmt = db.prepare(`
      SELECT COUNT(*) as count 
      FROM application_logs 
      WHERE timestamp >= datetime('now', '-1 day')
    `);
    stats.recent24h = recentStmt.get().count;
    
    return { success: true, statistics: stats };
  } catch (error) {
    logError('database', 'Failed to retrieve log statistics', { error: error.message });
    return { success: false, error: error.message };
  }
});

ipcMain.handle('export-logs', async (event, filters = {}) => {
  try {
    let query = `
      SELECT level, category, message, details, timestamp, userId, sessionId
      FROM application_logs
      WHERE 1=1
    `;
    const params = [];

    // Apply filters
    if (filters.level && filters.level !== 'all') {
      query += ' AND level = ?';
      params.push(filters.level);
    }

    if (filters.category && filters.category !== 'all') {
      query += ' AND category = ?';
      params.push(filters.category);
    }

    if (filters.startDate) {
      query += ' AND timestamp >= ?';
      params.push(filters.startDate);
    }

    if (filters.endDate) {
      query += ' AND timestamp <= ?';
      params.push(filters.endDate);
    }

    query += ' ORDER BY timestamp DESC';

    const stmt = db.prepare(query);
    const logs = stmt.all(...params);

    // Convert to CSV format
    const csvHeaders = ['Timestamp', 'Level', 'Category', 'Message', 'Details', 'User ID', 'Session ID'];
    const csvRows = logs.map(log => [
      log.timestamp,
      log.level,
      log.category,
      log.message,
      log.details || '',
      log.userId,
      log.sessionId
    ]);

    const csvContent = [csvHeaders, ...csvRows]
      .map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const defaultFilename = `application-logs-${timestamp}.csv`;
    
    // Show save dialog to let user choose location
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Application Logs',
      defaultPath: path.join(app.getPath('downloads'), defaultFilename),
      filters: [
        { name: 'CSV Files', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] }
      ],
      properties: ['createDirectory', 'showOverwriteConfirmation']
    });

    if (result.canceled) {
      logInfo('export', 'Log export cancelled by user');
      return { success: false, error: 'Export cancelled by user' };
    }

    const filePath = result.filePath;
    
    // Ensure the directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(filePath, csvContent);
    
    logInfo('export', 'Application logs exported', { filename: path.basename(filePath), filePath, recordCount: logs.length });
    
    return { success: true, filePath, filename: path.basename(filePath), recordCount: logs.length };
  } catch (error) {
    logError('export', 'Failed to export logs', { error: error.message });
    return { success: false, error: error.message };
  }
});

ipcMain.handle('clear-application-logs', async () => {
  try {
    const stmt = db.prepare('DELETE FROM application_logs');
    const result = stmt.run();
    
    logInfo('system', 'Application logs cleared', { deletedCount: result.changes });
    
    return { success: true, deletedCount: result.changes };
  } catch (error) {
    logError('database', 'Failed to clear application logs', { error: error.message });
    return { success: false, error: error.message };
  }
});

app.whenReady().then(async () => {
  try {
    logInfo('system', 'Application starting up');
    await initializeDatabase();
    createWindow();
    
    // Start the download scheduler
    startDownloadScheduler();
    logInfo('system', 'Download scheduler started');
    
    // Listen for feed download failures
    ipcMain.on('feed-download-failed', (event, data) => {
      logWarning('download', 'Feed download failed', data);
      // This will be handled by the renderer process
    });
    
    logInfo('system', 'Application startup completed successfully');
  } catch (error) {
    logError('system', 'Failed to initialize application', { error: error.message });
    console.error('Failed to initialize database:', error);
    app.quit();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  if (db) {
    db.close();
  }
}); 