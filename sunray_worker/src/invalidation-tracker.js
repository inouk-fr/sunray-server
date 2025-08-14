/**
 * InvalidationTracker - Prevents duplicate cache clearing from the same signal
 */

class InvalidationTracker {
  constructor() {
    // Track processed signal versions
    this.processed = new Map();
    // Prevent concurrent processing
    this.locks = new Map();
    // Track last invalidation time
    this.lastInvalidation = null;
    
    // Clean up old entries periodically
    this.startCleanup();
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
    if (lastProcessed && lastProcessed >= signalVersion) {
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
      if (currentProcessed && currentProcessed >= signalVersion) {
        return false;
      }
      
      console.log(`Processing signal ${key} v${signalVersion}`);
      
      // Mark as processed BEFORE clearing (prevents race conditions)
      this.processed.set(key, signalVersion);
      this.lastInvalidation = new Date().toISOString();
      
      // Execute the clear function
      await clearFunction();
      
      console.log(`Successfully processed signal ${key} v${signalVersion}`);
      
      // Schedule cleanup of this entry after 5 minutes
      setTimeout(() => {
        this.processed.delete(key);
      }, 300000);
      
      return true;
      
    } catch (error) {
      console.error(`Error processing signal ${key}:`, error);
      // Remove from processed on error so it can be retried
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
    return this.processed.size;
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
    this.processed.set(key, version);
    this.lastInvalidation = new Date().toISOString();
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
      processed_count: this.processed.size,
      last_invalidation: this.lastInvalidation
    };
  }
  
  /**
   * Start periodic cleanup of old entries
   */
  startCleanup() {
    // Clean up entries older than 5 minutes every minute
    setInterval(() => {
      this.cleanup();
    }, 60000); // Every minute
  }
  
  /**
   * Clean up old processed entries
   */
  cleanup() {
    const fiveMinutesAgo = Date.now() - 300000;
    let cleaned = 0;
    
    for (const [key, timestamp] of this.processed.entries()) {
      if (timestamp < fiveMinutesAgo) {
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

// Export the class for testing
export { InvalidationTracker };