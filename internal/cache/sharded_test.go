package cache

import (
	"testing"
	"time"
)

func TestValidationModes(t *testing.T) {
	// 1. Test Pass Mode
	t.Run("Pass Mode", func(t *testing.T) {
		c := NewShardedCache(Config{
			ValidationMode: ValidationModePass,
		})
		defer c.Close()

		entry := &Entry{
			QName:           "invalid.com",
			DNSSECValidated: false,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		hash := uint64(123)
		c.Set(hash, entry)

		if _, ok := c.Get(hash); !ok {
			t.Error("Pass mode should cache invalid entry")
		}
	})

	// 2. Test Enforced Mode
	t.Run("Enforced Mode", func(t *testing.T) {
		c := NewShardedCache(Config{
			ValidationMode: ValidationModeEnforced,
		})
		defer c.Close()

		// Invalid entry
		entry := &Entry{
			QName:           "invalid.com",
			DNSSECValidated: false,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		hash := uint64(123)
		c.Set(hash, entry)

		if _, ok := c.Get(hash); ok {
			t.Error("Enforced mode should NOT cache invalid entry")
		}

		// Valid entry
		validEntry := &Entry{
			QName:           "valid.com",
			DNSSECValidated: true,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		validHash := uint64(456)
		c.Set(validHash, validEntry)

		if _, ok := c.Get(validHash); !ok {
			t.Error("Enforced mode should cache valid entry")
		}
	})

	// 3. Test LogOnly Mode
	t.Run("LogOnly Mode", func(t *testing.T) {
		c := NewShardedCache(Config{
			ValidationMode: ValidationModeLogOnly,
		})
		defer c.Close()

		entry := &Entry{
			QName:           "invalid.com",
			DNSSECValidated: false,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		hash := uint64(123)
		c.Set(hash, entry)

		if _, ok := c.Get(hash); !ok {
			t.Error("LogOnly mode should cache invalid entry")
		}
	})
}
