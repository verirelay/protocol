package veriprov1

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Runtime Config identifier, store types and defaults. A store field that is
// absent takes its default; DefaultKeyPrefix is the namespace root of every
// Redis key.
const (
	RuntimeConfigVersion = "verirelay-runtime-config/1"

	StoreTypeRedis  = "redis"
	StoreTypeMemory = "memory"

	DefaultKeyPrefix              = "verirelay:"
	DefaultReceiptStoreTTLSeconds = 3600
	DefaultReceiptStoreMaxEntries = 10000
	DefaultRawStoreMaxBytes       = 256 << 20
)

// RuntimeConfigV1 is the Runtime Config sealed to the Guest in the HPKE
// envelope. An absent ReceiptStore is a memory store with the defaults. An
// absent RawStore uses the Redis connection and key prefix of a Redis
// ReceiptStore, and is otherwise a memory store with the defaults.
type RuntimeConfigV1 struct {
	Version      string                       `json:"version"`
	AdminToken   string                       `json:"admin_token"`
	ReceiptStore *RuntimeReceiptStoreConfigV1 `json:"receipt_store,omitempty"`
	RawStore     *RuntimeRawStoreConfigV1     `json:"raw_store,omitempty"`
}

// RuntimeReceiptStoreConfigV1 configures the Receipt store. Type is
// StoreTypeRedis or StoreTypeMemory. Addr, TLS, Username, Password, DB and
// KeyPrefix apply to Redis, MaxEntries to memory, and TTLSeconds to both;
// fields that do not apply to Type are ignored. A nil pointer field takes its
// default.
type RuntimeReceiptStoreConfigV1 struct {
	Type       string  `json:"type"`
	Addr       string  `json:"addr,omitempty"`
	TLS        bool    `json:"tls,omitempty"`
	Username   string  `json:"username,omitempty"`
	Password   string  `json:"password,omitempty"`
	DB         int     `json:"db,omitempty"`
	KeyPrefix  *string `json:"key_prefix,omitempty"`
	TTLSeconds *int64  `json:"ttl_seconds,omitempty"`
	MaxEntries *int    `json:"max_entries,omitempty"`
}

// RuntimeRawStoreConfigV1 configures the Raw Capture store. Type is
// StoreTypeRedis or StoreTypeMemory. Addr, TLS, Username, Password, DB and
// KeyPrefix apply to Redis, MaxBytes to memory, and MaxTTLSeconds to both;
// fields that do not apply to Type are ignored. MaxTTLSeconds caps the
// retention a client may request, and 0 means no cap. A nil pointer field
// takes its default.
type RuntimeRawStoreConfigV1 struct {
	Type          string  `json:"type"`
	Addr          string  `json:"addr,omitempty"`
	TLS           bool    `json:"tls,omitempty"`
	Username      string  `json:"username,omitempty"`
	Password      string  `json:"password,omitempty"`
	DB            int     `json:"db,omitempty"`
	KeyPrefix     *string `json:"key_prefix,omitempty"`
	MaxTTLSeconds int64   `json:"max_ttl_seconds,omitempty"`
	MaxBytes      *int64  `json:"max_bytes,omitempty"`
}

// Validate requires the RuntimeConfigVersion version, a non-empty admin_token
// without leading or trailing whitespace, and valid stores when set.
func (config RuntimeConfigV1) Validate() error {
	if config.Version != RuntimeConfigVersion {
		return fmt.Errorf("version = %q, want %q", config.Version, RuntimeConfigVersion)
	}
	if config.AdminToken == "" {
		return errors.New("admin_token must not be empty")
	}
	if strings.TrimSpace(config.AdminToken) != config.AdminToken {
		return errors.New("admin_token must not contain leading or trailing whitespace")
	}
	if config.ReceiptStore != nil {
		if err := config.ReceiptStore.validate(); err != nil {
			return fmt.Errorf("receipt_store.%w", err)
		}
	}
	if config.RawStore != nil {
		if err := config.RawStore.validate(); err != nil {
			return fmt.Errorf("raw_store.%w", err)
		}
	}
	return nil
}

func (store RuntimeReceiptStoreConfigV1) validate() error {
	switch store.Type {
	case StoreTypeRedis:
		if err := validateRedisStore(store.Addr, store.DB, store.KeyPrefix); err != nil {
			return err
		}
	case StoreTypeMemory:
		if store.MaxEntries != nil && *store.MaxEntries <= 0 {
			return errors.New("max_entries must be positive")
		}
	default:
		return invalidStoreType(store.Type)
	}
	if store.TTLSeconds != nil && *store.TTLSeconds <= 0 {
		return errors.New("ttl_seconds must be positive")
	}
	return nil
}

func (store RuntimeRawStoreConfigV1) validate() error {
	switch store.Type {
	case StoreTypeRedis:
		if err := validateRedisStore(store.Addr, store.DB, store.KeyPrefix); err != nil {
			return err
		}
	case StoreTypeMemory:
		if store.MaxBytes != nil && *store.MaxBytes <= 0 {
			return errors.New("max_bytes must be positive")
		}
	default:
		return invalidStoreType(store.Type)
	}
	if store.MaxTTLSeconds < 0 {
		return errors.New("max_ttl_seconds must not be negative")
	}
	return nil
}

func validateRedisStore(addr string, db int, keyPrefix *string) error {
	if strings.TrimSpace(addr) == "" {
		return errors.New("addr must not be empty")
	}
	if db < 0 {
		return errors.New("db must not be negative")
	}
	if keyPrefix != nil && *keyPrefix == "" {
		return errors.New("key_prefix must not be empty")
	}
	return nil
}

func invalidStoreType(storeType string) error {
	return fmt.Errorf("type = %q, want %q or %q", storeType, StoreTypeRedis, StoreTypeMemory)
}

// DurationFromSeconds converts seconds to a Duration, saturating at the
// largest or smallest Duration instead of overflowing.
func DurationFromSeconds(seconds int64) time.Duration {
	const limit = math.MaxInt64 / int64(time.Second)
	switch {
	case seconds > limit:
		return math.MaxInt64
	case seconds < -limit:
		return math.MinInt64
	}
	return time.Duration(seconds) * time.Second
}
