const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Feed operations
  getFeeds: () => ipcRenderer.invoke('db-get-feeds'),
  addFeed: (feedData) => ipcRenderer.invoke('db-add-feed', feedData),
  updateFeed: (feedData) => ipcRenderer.invoke('db-update-feed', feedData),
  deleteFeed: (id) => ipcRenderer.invoke('db-delete-feed', id),
  
  // IOC operations
  getIOCs: () => ipcRenderer.invoke('get-iocs'),
  deleteIOC: (id) => ipcRenderer.invoke('delete-ioc', id),
  
  // Settings operations
  getSettings: () => ipcRenderer.invoke('db-get-settings'),
  updateSettings: (settings) => ipcRenderer.invoke('db-update-settings', settings),
  
  // Download operations
  manualDownload: () => ipcRenderer.invoke('manual-download'),
  retryFailedFeed: (feedId) => ipcRenderer.invoke('retry-failed-feed', feedId),
  getDownloadLogs: () => ipcRenderer.invoke('get-download-logs'),
  getDownloadLogDetails: (logId) => ipcRenderer.invoke('get-download-log-details', logId),
  getDownloadSettings: () => ipcRenderer.invoke('get-download-settings'),
  updateDownloadPath: (path) => ipcRenderer.invoke('update-download-path', path),
  updateDownloadTime: (time) => ipcRenderer.invoke('update-download-time', time),
  pauseDownloadScheduler: () => ipcRenderer.invoke('pause-download-scheduler'),
  resumeDownloadScheduler: () => ipcRenderer.invoke('resume-download-scheduler'),
  getSchedulerStatus: () => ipcRenderer.invoke('get-scheduler-status'),
  getIOCsCount: () => ipcRenderer.invoke('get-iocs-count'),
  getFeedsCount: () => ipcRenderer.invoke('get-feeds-count'),
  getLogsCount: () => ipcRenderer.invoke('get-logs-count'),
  clearDownloadLogs: () => ipcRenderer.invoke('clear-download-logs'),
  clearIOCs: () => ipcRenderer.invoke('clear-iocs'),
  
  // Application logs operations
  getApplicationLogs: (filters) => ipcRenderer.invoke('get-application-logs', filters),
  getLogStatistics: () => ipcRenderer.invoke('get-log-statistics'),
  exportLogs: (filters) => ipcRenderer.invoke('export-logs', filters),
  clearApplicationLogs: () => ipcRenderer.invoke('clear-application-logs'),
  
  // Settings operations
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  exportFeeds: () => ipcRenderer.invoke('export-feeds'),
  exportIOCs: () => ipcRenderer.invoke('export-iocs'),
  wipeAllData: () => ipcRenderer.invoke('wipe-all-data'),
  
  // Listen for feed download failures
  onFeedDownloadFailed: (callback) => {
    ipcRenderer.on('feed-download-failed', (event, data) => callback(data));
  },
  
  // Utility functions
  showMessage: (message) => {
    // You can implement native notifications here
    console.log(message);
  },

  setSessionEncryptionKey: (password) => ipcRenderer.invoke('set-session-encryption-key', { password }),
  clearSessionEncryptionKey: () => ipcRenderer.invoke('clear-session-encryption-key'),
  encryptionStatus: () => ipcRenderer.invoke('encryption-status'),
  setupEncryption: (masterPassword) => ipcRenderer.invoke('setup-encryption', { masterPassword }),
  disableEncryption: () => ipcRenderer.invoke('disable-encryption'),
}); 