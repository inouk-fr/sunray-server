/**
 * InvalidationTracker - Prevents duplicate cache clearing from the same signal
 */

class InvalidationTracker {
  constructor() {
    // Track processed signal versions with timestamps
    this.processed = new Map();
    // Prevent concurrent processing
    this.locks = new Map();
    // Track last invalidation time
    this.lastInvalidation = null;
    // Track cumulative processed count
    this.cumulativeCount = 0;
    
    // Clean up old entries periodically
    this.startCleanup();
  }
  
  /**
   * Get the singleton instance (for test compatibility)
   */
  static getInstance() {
    return getInvalidationTracker();
  }
  
  /**
   * Process a signal, ensuring it's only processed once
   * @param {string} key - Signal key
   * @param {number} signalVersion - Signal version/timestamp
   * @param {Function} clearFunction - Function to execute for clearing
   * @returns {boolean} - Whether the signal was processed
   */
  async processSignal(key, signalVersion, clearFunction) {
    // Check if already processed
    const lastProcessed = this.processed.get(key);
    if (lastProcessed && lastProcessed.version >= signalVersion) {
      console.log(`Signal ${key} v${signalVersion} already processed`);
      return false; // Already processed this or newer version
    }
    
    // Check if currently processing (prevent race condition)
    if (this.locks.has(key)) {
      console.log(`Signal ${key} is currently being processed`);
      return false; // Another request is handling it
    }
    
    // Claim the lock
    this.locks.set(key, true);
    
    try {
      // Double-check after acquiring lock
      const currentProcessed = this.processed.get(key);
      if (currentProcessed && currentProcessed.version >= signalVersion) {
        return false;
      }
      
      console.log(`Processing signal ${key} v${signalVersion}`);
      
      // Mark as processed BEFORE clearing (prevents race conditions)
      const timestamp = Date.now();
      this.processed.set(key, { version: signalVersion, timestamp });
      this.lastInvalidation = new Date().toISOString();
      this.cumulativeCount++;
      
      // Execute the clear function
      await clearFunction();
      
      console.log(`Successfully processed signal ${key} v${signalVersion}`);
      
      // Individual cleanup is handled by periodic cleanup now
      // setTimeout(() => {
      //   this.processed.delete(key);
      // }, 300000);
      
      return true;
      
    } catch (error) {
      console.error(`Error processing signal ${key}:`, error);
      // Remove from processed on error so it can be retried (don't decrement count)
      this.processed.delete(key);
      throw error;
      
    } finally {
      // Always release the lock
      this.locks.delete(key);
    }
  }
  
  /**
   * Get count of processed signals
   */
  getProcessedCount() {
    return this.cumulativeCount;
  }
  
  /**
   * Get last invalidation timestamp
   */
  getLastInvalidation() {
    return this.lastInvalidation;
  }
  
  /**
   * Mark a signal as processed (for testing)
   */
  markProcessed(key, version = Date.now()) {
    const timestamp = Date.now();
    this.processed.set(key, { version, timestamp });
    this.lastInvalidation = new Date().toISOString();
    this.cumulativeCount++; // Always increment, even for duplicates (as per test expectations)
  }
  
  /**
   * Check if signal has been processed (for testing)
   */
  hasProcessed(key) {
    return this.processed.has(key);
  }
  
  /**
   * Get statistics (for testing)
   */
  getStats() {
    return {
      processed_count: this.cumulativeCount,
      last_invalidation: this.lastInvalidation || 'Never'
    };
  }
  
  /**
   * Start periodic cleanup of old entries
   */
  startCleanup() {
    // Clean up entries older than 5 minutes every minute
    this.cleanupIntervalId = setInterval(() => {
      this.cleanup();
    }, 60000); // Every minute
  }
  
  /**
   * Clean up old processed entries
   */
  cleanup() {
    const fiveMinutesAgo = Date.now() - 300000;
    let cleaned = 0;
    
    for (const [key, data] of this.processed.entries()) {
      if (data.timestamp < fiveMinutesAgo) {
        this.processed.delete(key);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      console.log(`Cleaned up ${cleaned} old invalidation entries`);
    }
  }
  
  /**
   * Clear all tracking (for testing)
   */
  clear() {
    this.processed.clear();
    this.locks.clear();
    this.lastInvalidation = null;
    this.cumulativeCount = 0;
    // Clear interval to prevent memory leaks in tests
    if (this.cleanupIntervalId) {
      clearInterval(this.cleanupIntervalId);
      this.cleanupIntervalId = null;
    }
  }
}

// Singleton instance
let tracker = null;

/**
 * Get the singleton InvalidationTracker instance
 */
export function getInvalidationTracker() {
  if (!tracker) {
    tracker = new InvalidationTracker();
  }
  return tracker;
}

/**
 * Reset the singleton for testing
 */
export function resetInvalidationTracker() {
  if (tracker && tracker.cleanupIntervalId) {
    clearInterval(tracker.cleanupIntervalId);
  }
  tracker = null;
}

// Export the class for testing
export { InvalidationTracker };