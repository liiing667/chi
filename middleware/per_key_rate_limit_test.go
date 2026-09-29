package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func perKeyTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func doPerKeyRequest(h http.Handler, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPerKeyRateLimitAllowsBurstThenRejects(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: 3, MaxKeys: 100})(perKeyTestHandler())

	for i := 0; i < 3; i++ {
		if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	rec := doPerKeyRequest(h, "a")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	retryAfter := rec.Header().Get("Retry-After")
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil || seconds < 1 {
		t.Fatalf("expected Retry-After of at least 1 whole second, got %q", retryAfter)
	}
}

func TestPerKeyRateLimitKeysAreIsolated(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: 1, MaxKeys: 100})(perKeyTestHandler())

	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for exhausted key a, got %d", rec.Code)
	}
	if rec := doPerKeyRequest(h, "b"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for fresh key b, got %d", rec.Code)
	}
}

func TestPerKeyRateLimitRefillsOverTime(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 20, Burst: 1, MaxKeys: 100})(perKeyTestHandler())

	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	time.Sleep(100 * time.Millisecond) // 2 tokens at 20/s, capped at burst of 1

	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after refill, got %d", rec.Code)
	}
}

func TestPerKeyRateLimitCustomKeyFunc(t *testing.T) {
	opts := PerKeyOpts{
		Rate:    1,
		Burst:   1,
		MaxKeys: 100,
		KeyFunc: func(r *http.Request) string { return r.Header.Get("X-Tenant") },
	}
	h := PerKeyRateLimit(opts)(perKeyTestHandler())

	newReq := func(tenant string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Tenant", tenant)
		return req
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq("t1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, newReq("t1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}

func TestPerKeyRateLimitLRUEviction(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: 1, MaxKeys: 2})(perKeyTestHandler())

	// Fill buckets for a and b, exhausting both.
	for _, key := range []string{"a", "b"} {
		if rec := doPerKeyRequest(h, key); rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for key %q, got %d", key, rec.Code)
		}
		if rec := doPerKeyRequest(h, key); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 for key %q, got %d", key, rec.Code)
		}
	}

	// A new key c must evict the least recently used bucket (a).
	if rec := doPerKeyRequest(h, "c"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for key c, got %d", rec.Code)
	}

	// b was kept and stays exhausted.
	if rec := doPerKeyRequest(h, "b"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for retained key b, got %d", rec.Code)
	}
	// a was evicted, so it gets a fresh full bucket.
	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for evicted key a, got %d", rec.Code)
	}
}

func TestPerKeyRateLimitEmptyKeyBypass(t *testing.T) {
	opts := PerKeyOpts{Rate: 1, Burst: 1, MaxKeys: 100, EmptyKeyPolicy: EmptyKeyBypass}
	h := PerKeyRateLimit(opts)(perKeyTestHandler())

	for i := 0; i < 10; i++ {
		if rec := doPerKeyRequest(h, ""); rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 for empty key, got %d", i+1, rec.Code)
		}
	}
}

func TestPerKeyRateLimitEmptyKeyShared(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: 2, MaxKeys: 100})(perKeyTestHandler())

	// Empty keys share one default bucket of capacity 2.
	for i := 0; i < 2; i++ {
		if rec := doPerKeyRequest(h, ""); rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
	if rec := doPerKeyRequest(h, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for shared empty-key bucket, got %d", rec.Code)
	}
	// Named keys are unaffected.
	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for named key, got %d", rec.Code)
	}
}

func TestPerKeyRateLimitZeroBurst(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for burst 0 without AllowZeroBurst")
		}
	}()
	PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: 0, MaxKeys: 100})
}

func TestPerKeyRateLimitZeroBurstAllowed(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: 0, AllowZeroBurst: true, MaxKeys: 100})(perKeyTestHandler())

	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec := doPerKeyRequest(h, "a"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}

func TestPerKeyRateLimitInvalidOpts(t *testing.T) {
	tests := []PerKeyOpts{
		{Rate: 0, Burst: 1, MaxKeys: 100},
		{Rate: -1, Burst: 1, MaxKeys: 100},
		{Rate: 1, Burst: -1, MaxKeys: 100},
		{Rate: 1, Burst: 1, MaxKeys: 0},
	}
	for i, opts := range tests {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("opts %d: expected panic", i)
				}
			}()
			PerKeyRateLimit(opts)
		}()
	}
}

func TestPerKeyRateLimitConcurrentSameNewKey(t *testing.T) {
	const burst = 25
	h := PerKeyRateLimit(PerKeyOpts{Rate: 1, Burst: burst, MaxKeys: 100})(perKeyTestHandler())

	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	// All goroutines race against the same brand-new key; exactly `burst`
	// requests may pass, proving no duplicate buckets are created.
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if rec := doPerKeyRequest(h, "new-key"); rec.Code == http.StatusOK {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := allowed.Load(); got != burst {
		t.Fatalf("expected exactly %d allowed requests, got %d", burst, got)
	}
}

func TestPerKeyRateLimitConcurrentManyKeys(t *testing.T) {
	h := PerKeyRateLimit(PerKeyOpts{Rate: 100, Burst: 5, MaxKeys: 1000})(perKeyTestHandler())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", i)
			for j := 0; j < 20; j++ {
				doPerKeyRequest(h, key)
			}
		}(i)
	}
	wg.Wait()
}
