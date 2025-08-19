import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { getInvalidationTracker, InvalidationTracker, resetInvalidationTracker } from './invalidation-tracker.js';

describe('InvalidationTracker', () => {
  let tracker;

  beforeEach(() => {
    vi.useFakeTimers();
    // Get a fresh tracker instance
    tracker = getInvalidationTracker();
    // Clear any existing state completely
    tracker.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Singleton pattern', () => {
    it('should return the same instance', () => {
      const tracker1 = getInvalidationTracker();
      const tracker2 = getInvalidationTracker();
      expect(tracker1).toBe(tracker2);
    });

    it('should maintain state across function calls', async () => {
      const tracker1 = getInvalidationTracker();
      await tracker1.processSignal('test_signal', 1000, async () => {});
      
      const tracker2 = getInvalidationTracker();
      // Check if signal was processed by looking at the processed state
      const result = await tracker2.processSignal('test_signal', 1000, async () => {});
      expect(result).toBe(false); // Should not process again
    });
  });

  describe('Signal processing', () => {
    it('should process new signals', async () => {
      let processed = false;
      const result = await tracker.processSignal('signal1', 1000, async () => {
        processed = true;
      });
      
      expect(result).toBe(true);
      expect(processed).toBe(true);
    });

    it('should handle multiple different signals', async () => {
      const processedSignals = [];
      
      await tracker.processSignal('signal1', 1000, async () => {
        processedSignals.push('signal1');
      });
      await tracker.processSignal('signal2', 1001, async () => {
        processedSignals.push('signal2');
      });
      await tracker.processSignal('signal3', 1002, async () => {
        processedSignals.push('signal3');
      });
      
      expect(processedSignals).toContain('signal1');
      expect(processedSignals).toContain('signal2');
      expect(processedSignals).toContain('signal3');
      expect(processedSignals.length).toBe(3);
    });

    it('should update last invalidation timestamp', async () => {
      const now = new Date('2025-01-14T12:00:00Z');
      vi.setSystemTime(now);
      
      await tracker.processSignal('signal1', 1000, async () => {});
      
      const lastInvalidation = tracker.getLastInvalidation();
      expect(lastInvalidation).toBe(now.toISOString());
    });

    it('should increment processed count', async () => {
      const initialCount = tracker.getProcessedCount();
      
      await tracker.processSignal('signal1', 1000, async () => {});
      await tracker.processSignal('signal2', 1001, async () => {});
      
      const finalCount = tracker.getProcessedCount();
      expect(finalCount).toBe(initialCount + 2);
    });
  });

  describe('Automatic cleanup', () => {
    it('should clean up old signals after 5 minutes', () => {
      const now = new Date('2025-01-14T12:00:00Z');
      vi.setSystemTime(now);
      
      tracker.markProcessed('old_signal');
      expect(tracker.hasProcessed('old_signal')).toBe(true);
      
      // Advance time by 4 minutes - signal should still exist
      vi.advanceTimersByTime(4 * 60 * 1000);
      expect(tracker.hasProcessed('old_signal')).toBe(true);
      
      // Advance time by another 2 minutes (total 6 minutes) - signal should be cleaned
      vi.advanceTimersByTime(2 * 60 * 1000);
      tracker.cleanup(); // Manually trigger cleanup since setInterval doesn't work with fake timers
      expect(tracker.hasProcessed('old_signal')).toBe(false);
    });

    it('should keep recent signals during cleanup', () => {
      const now = new Date('2025-01-14T12:00:00Z');
      vi.setSystemTime(now);
      
      // Add old signal
      tracker.markProcessed('old_signal');
      
      // Advance time by 4 minutes
      vi.advanceTimersByTime(4 * 60 * 1000);
      
      // Add new signal
      tracker.markProcessed('new_signal');
      
      // Advance time by 2 more minutes (old signal is 6 minutes old, new is 2 minutes)
      vi.advanceTimersByTime(2 * 60 * 1000);
      tracker.cleanup(); // Manually trigger cleanup
      
      expect(tracker.hasProcessed('old_signal')).toBe(false);
      expect(tracker.hasProcessed('new_signal')).toBe(true);
    });

    it('should handle multiple cleanup cycles', () => {
      const now = new Date('2025-01-14T12:00:00Z');
      vi.setSystemTime(now);
      
      // First batch of signals
      tracker.markProcessed('signal1');
      vi.advanceTimersByTime(2 * 60 * 1000);
      tracker.markProcessed('signal2');
      vi.advanceTimersByTime(2 * 60 * 1000);
      tracker.markProcessed('signal3');
      
      // All should still exist (oldest is 4 minutes)
      expect(tracker.hasProcessed('signal1')).toBe(true);
      expect(tracker.hasProcessed('signal2')).toBe(true);
      expect(tracker.hasProcessed('signal3')).toBe(true);
      
      // Advance to trigger cleanup of signal1
      vi.advanceTimersByTime(2 * 60 * 1000);
      tracker.cleanup(); // Manually trigger cleanup
      
      expect(tracker.hasProcessed('signal1')).toBe(false);
      expect(tracker.hasProcessed('signal2')).toBe(true);
      expect(tracker.hasProcessed('signal3')).toBe(true);
      
      // Advance to trigger cleanup of signal2
      vi.advanceTimersByTime(2 * 60 * 1000);
      tracker.cleanup(); // Manually trigger cleanup
      
      expect(tracker.hasProcessed('signal1')).toBe(false);
      expect(tracker.hasProcessed('signal2')).toBe(false);
      expect(tracker.hasProcessed('signal3')).toBe(true);
    });
  });

  describe('Statistics', () => {
    it('should return initial stats', () => {
      const stats = tracker.getStats();
      
      expect(stats).toHaveProperty('processed_count');
      expect(stats).toHaveProperty('last_invalidation');
      expect(typeof stats.processed_count).toBe('number');
    });

    it('should track cumulative processed count', () => {
      const initialStats = tracker.getStats();
      const initialCount = initialStats.processed_count;
      
      // Process some signals
      tracker.markProcessed('signal1');
      tracker.markProcessed('signal2');
      tracker.markProcessed('signal3');
      
      // Process duplicate (should still increment count)
      tracker.markProcessed('signal1');
      
      const stats = tracker.getStats();
      expect(stats.processed_count).toBe(initialCount + 4);
    });

    it('should update last invalidation with each signal', () => {
      const time1 = new Date('2025-01-14T12:00:00Z');
      vi.setSystemTime(time1);
      tracker.markProcessed('signal1');
      
      const stats1 = tracker.getStats();
      expect(stats1.last_invalidation).toBe(time1.toISOString());
      
      const time2 = new Date('2025-01-14T12:05:00Z');
      vi.setSystemTime(time2);
      tracker.markProcessed('signal2');
      
      const stats2 = tracker.getStats();
      expect(stats2.last_invalidation).toBe(time2.toISOString());
    });

    it('should handle never having processed signals', () => {
      // Reset the singleton to get a truly fresh instance
      resetInvalidationTracker();
      const newTracker = InvalidationTracker.getInstance();
      const stats = newTracker.getStats();
      
      expect(stats.processed_count).toBe(0);
      expect(stats.last_invalidation).toBe('Never');
    });
  });

  describe('Edge cases', () => {
    it('should handle empty signal identifiers', () => {
      tracker.markProcessed('');
      expect(tracker.hasProcessed('')).toBe(true);
    });

    it('should handle special characters in signals', () => {
      const specialSignal = 'user_test@example.com_!@#$%^&*()';
      tracker.markProcessed(specialSignal);
      expect(tracker.hasProcessed(specialSignal)).toBe(true);
    });

    it('should handle very long signal identifiers', () => {
      const longSignal = 'a'.repeat(1000);
      tracker.markProcessed(longSignal);
      expect(tracker.hasProcessed(longSignal)).toBe(true);
    });

    it('should handle concurrent markProcessed calls', () => {
      const signals = Array.from({ length: 100 }, (_, i) => `signal${i}`);
      
      // Mark all signals as processed
      signals.forEach(signal => tracker.markProcessed(signal));
      
      // Verify all were tracked
      signals.forEach(signal => {
        expect(tracker.hasProcessed(signal)).toBe(true);
      });
      
      const stats = tracker.getStats();
      expect(stats.processed_count).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Memory management', () => {
    it('should not grow indefinitely with cleanup', () => {
      const now = new Date('2025-01-14T12:00:00Z');
      vi.setSystemTime(now);
      
      // Add many signals over time
      for (let i = 0; i < 1000; i++) {
        tracker.markProcessed(`signal${i}`);
        
        // Advance time slightly for each signal
        vi.advanceTimersByTime(1000); // 1 second
      }
      
      // Trigger cleanup to simulate periodic cleanup
      tracker.cleanup();
      
      // Count how many are still tracked
      let activeCount = 0;
      for (let i = 0; i < 1000; i++) {
        if (tracker.hasProcessed(`signal${i}`)) {
          activeCount++;
        }
      }
      
      // Should have cleaned up old ones (only ~300 seconds worth should remain)
      expect(activeCount).toBeLessThan(350); // Allow some margin
      expect(activeCount).toBeGreaterThan(250); // But should keep recent ones
    });
  });
});