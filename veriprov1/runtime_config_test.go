package veriprov1

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func decodeRuntimeConfig(data string) (RuntimeConfigV1, error) {
	var config RuntimeConfigV1
	if err := DecodeJSON([]byte(data), &config); err != nil {
		return RuntimeConfigV1{}, err
	}
	return config, config.Validate()
}

func TestRuntimeConfigGoldenFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/verirelay_runtime_config_valid.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeRuntimeConfig(string(data))
	if err != nil {
		t.Fatal(err)
	}
	receipt, raw := config.ReceiptStore, config.RawStore
	if config.AdminToken != "test-only-admin-token" || receipt == nil || raw == nil {
		t.Fatalf("decoded %+v", config)
	}
	if receipt.Type != StoreTypeRedis || !receipt.TLS || *receipt.KeyPrefix != DefaultKeyPrefix || *receipt.TTLSeconds != DefaultReceiptStoreTTLSeconds {
		t.Fatalf("receipt_store = %+v", receipt)
	}
	if raw.Type != StoreTypeMemory || raw.MaxTTLSeconds != 86400 || *raw.MaxBytes != DefaultRawStoreMaxBytes {
		t.Fatalf("raw_store = %+v", raw)
	}
}

func TestRuntimeConfigMinimal(t *testing.T) {
	config, err := decodeRuntimeConfig(`{"version":"verirelay-runtime-config/1","admin_token":"token"}`)
	if err != nil {
		t.Fatal(err)
	}
	if config.ReceiptStore != nil || config.RawStore != nil {
		t.Fatalf("absent stores decoded as %+v", config)
	}
}

func TestRuntimeConfigIsLenient(t *testing.T) {
	for _, data := range []string{
		`{"version":"verirelay-runtime-config/1","admin_token":"token","future":{"x":1}}`,
		`{"version":"verirelay-runtime-config/1","admin_token":"token","upstreams":[{"name":"x"}]}`,
		`{"version":"verirelay-runtime-config/1","admin_token":"token","receipt_store":{"type":"memory","future":true}}`,
		`{"version":"verirelay-runtime-config/1","admin_token":"token","receipt_store":{"type":"memory","addr":"ignored:6379","max_ttl_seconds":-1}}`,
		`{"version":"verirelay-runtime-config/1","admin_token":"token","raw_store":{"type":"redis","addr":"redis:6379","max_entries":-1,"ttl_seconds":-1}}`,
	} {
		if _, err := decodeRuntimeConfig(data); err != nil {
			t.Errorf("%s: %v", data, err)
		}
	}
}

func TestRuntimeConfigStoreDefaultsAndTypes(t *testing.T) {
	for _, data := range []string{
		`{"type":"memory"}`,
		`{"type":"memory","ttl_seconds":1,"max_entries":1}`,
		`{"type":"redis","addr":"redis:6379"}`,
		`{"type":"redis","addr":"redis:6379","db":15,"key_prefix":"tenant-a:","ttl_seconds":9223372036854775807}`,
	} {
		if _, err := decodeRuntimeConfig(`{"version":"verirelay-runtime-config/1","admin_token":"token","receipt_store":` + data + `}`); err != nil {
			t.Errorf("receipt_store %s: %v", data, err)
		}
	}
	for _, data := range []string{
		`{"type":"memory"}`,
		`{"type":"memory","max_bytes":1,"max_ttl_seconds":0}`,
		`{"type":"redis","addr":"redis:6379","key_prefix":"x","max_ttl_seconds":86400}`,
	} {
		if _, err := decodeRuntimeConfig(`{"version":"verirelay-runtime-config/1","admin_token":"token","raw_store":` + data + `}`); err != nil {
			t.Errorf("raw_store %s: %v", data, err)
		}
	}
}

func TestRuntimeConfigRejectsEachRule(t *testing.T) {
	const prefix = `{"version":"verirelay-runtime-config/1","admin_token":"token",`
	for _, tc := range []struct {
		data   string
		detail string
	}{
		{`{"admin_token":"token"}`, "version"},
		{`{"version":"verirelay-runtime-config-v1","admin_token":"token"}`, "version"},
		{`{"version":"verirelay-runtime-config/1"}`, "admin_token must not be empty"},
		{`{"version":"verirelay-runtime-config/1","admin_token":""}`, "admin_token must not be empty"},
		{`{"version":"verirelay-runtime-config/1","admin_token":" token"}`, "admin_token must not contain"},
		{`{"version":"verirelay-runtime-config/1","admin_token":"token\n"}`, "admin_token must not contain"},
		{prefix + `"receipt_store":{}}`, "receipt_store.type"},
		{prefix + `"receipt_store":{"type":"valkey","addr":"redis:6379"}}`, "receipt_store.type"},
		{prefix + `"receipt_store":{"type":"redis"}}`, "receipt_store.addr"},
		{prefix + `"receipt_store":{"type":"redis","addr":" "}}`, "receipt_store.addr"},
		{prefix + `"receipt_store":{"type":"redis","addr":"redis:6379","db":-1}}`, "receipt_store.db"},
		{prefix + `"receipt_store":{"type":"redis","addr":"redis:6379","key_prefix":""}}`, "receipt_store.key_prefix"},
		{prefix + `"receipt_store":{"type":"redis","addr":"redis:6379","ttl_seconds":0}}`, "receipt_store.ttl_seconds"},
		{prefix + `"receipt_store":{"type":"memory","ttl_seconds":-1}}`, "receipt_store.ttl_seconds"},
		{prefix + `"receipt_store":{"type":"memory","max_entries":0}}`, "receipt_store.max_entries"},
		{prefix + `"raw_store":{"type":""}}`, "raw_store.type"},
		{prefix + `"raw_store":{"type":"redis","key_prefix":"x"}}`, "raw_store.addr"},
		{prefix + `"raw_store":{"type":"redis","addr":"redis:6379","db":-1}}`, "raw_store.db"},
		{prefix + `"raw_store":{"type":"redis","addr":"redis:6379","key_prefix":""}}`, "raw_store.key_prefix"},
		{prefix + `"raw_store":{"type":"redis","addr":"redis:6379","max_ttl_seconds":-1}}`, "raw_store.max_ttl_seconds"},
		{prefix + `"raw_store":{"type":"memory","max_bytes":0}}`, "raw_store.max_bytes"},
		{prefix + `"raw_store":{"type":"memory","max_ttl_seconds":-1}}`, "raw_store.max_ttl_seconds"},
	} {
		_, err := decodeRuntimeConfig(tc.data)
		if err == nil || !strings.Contains(err.Error(), tc.detail) {
			t.Errorf("%s: err = %v, want %q", tc.data, err, tc.detail)
		}
	}
	for _, data := range []string{
		prefix + `"receipt_store":{"type":"memory","ttl_seconds":1,"ttl_seconds":2}}`,
		prefix + `"receipt_store":{"type":"memory","TTL_Seconds":1}}`,
		prefix + `"receipt_store":{"type":"memory","ttl_seconds":"1"}}`,
		prefix + `"receipt_store":{"type":"memory","ttl_seconds":1.5}}`,
		prefix + `"receipt_store":{"type":"memory","ttl_seconds":9223372036854775808}}`,
	} {
		if _, err := decodeRuntimeConfig(data); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}

func TestDurationFromSecondsSaturates(t *testing.T) {
	for seconds, want := range map[int64]time.Duration{
		0:             0,
		3600:          time.Hour,
		-1:            -time.Second,
		9223372036:    9223372036 * time.Second,
		9223372037:    math.MaxInt64,
		math.MaxInt64: math.MaxInt64,
		-9223372037:   math.MinInt64,
		math.MinInt64: math.MinInt64,
	} {
		if got := DurationFromSeconds(seconds); got != want {
			t.Errorf("DurationFromSeconds(%d) = %d, want %d", seconds, got, want)
		}
	}
}
