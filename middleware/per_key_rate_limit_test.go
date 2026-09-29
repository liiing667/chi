package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func perKeyTestRouter(opts PerKeyOpts) *chi.Mux {
	r := chi.NewRouter()
	r.Use(PerKeyRateLimit(opts))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func doPerKeyRequest(t *testing.T, server *httptest.Server, key string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	assertNoError(t, err)
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	res, err := http.DefaultClient.Do(req)
	assertNoError(t, err)
	defer res.Body.Close()
	return res
}

func TestPerKeyRateLimitIsolatesKeys(t *testing.T) {
	server := httptest.NewServer(perKeyTestRouter(PerKeyOpts{Rate: 1, Burst: 2, MaxKeys: 100}))
	defer server.Close()

	// Key A exhausts its burst.
	for range 2 {
		assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "a").StatusCode)
	}
	assertEqual(t, http.StatusTooManyRequests, doPerKeyRequest(t, server, "a").StatusCode)

	// Key B is unaffected.
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "b").StatusCode)
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "b").StatusCode)
	assertEqual(t, http.StatusTooManyRequests, doPerKeyRequest(t, server, "b").StatusCode)
}

func TestPerKeyRateLimitRetryAfter(t *testing.T) {
	server := httptest.NewServer(perKeyTestRouter(PerKeyOpts{Rate: 0.5, Burst: 1, MaxKeys: 100}))
	defer server.Close()

	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "a").StatusCode)

	res := doPerKeyRequest(t, server, "a")
	assertEqual(t, http.StatusTooManyRequests, res.StatusCode)
	retryAfter := res.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}
	seconds, err := strconv.Atoi(retryAfter)
	assertNoError(t, err)
	// One token at 0.5 tokens/sec takes 2s; rounded up to whole seconds.
	assertEqual(t, 2, seconds)
}

func TestPerKeyRateLimitRefills(t *testing.T) {
	server := httptest.NewServer(perKeyTestRouter(PerKeyOpts{Rate: 20, Burst: 1, MaxKeys: 100}))
	defer server.Close()

	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "a").StatusCode)
	assertEqual(t, http.StatusTooManyRequests, doPerKeyRequest(t, server, "a").StatusCode)

	time.Sleep(100 * time.Millisecond) // 20 tokens/sec => a token every 50ms.
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "a").StatusCode)
}

func TestPerKeyRateLimitCustomKeyFunc(t *testing.T) {
	opts := PerKeyOpts{
		Rate:    1,
		Burst:   1,
		MaxKeys: 100,
		KeyFunc: func(r *http.Request) string { return r.Header.Get("X-Tenant") },
	}
	server := httptest.NewServer(perKeyTestRouter(opts))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	assertNoError(t, err)
	req.Header.Set("X-Api-Key", "ignored")
	req.Header.Set("X-Tenant", "tenant-1")
	res, err := http.DefaultClient.Do(req)
	assertNoError(t, err)
	res.Body.Close()
	assertEqual(t, http.StatusOK, res.StatusCode)

	// Same tenant via the custom header is limited, even with a different API key.
	req.Header.Set("X-Api-Key", "other")
	res, err = http.DefaultClient.Do(req)
	assertNoError(t, err)
	res.Body.Close()
	assertEqual(t, http.StatusTooManyRequests, res.StatusCode)
}

func TestPerKeyRateLimitEmptyKeyBypass(t *testing.T) {
	opts := PerKeyOpts{Rate: 1, Burst: 1, MaxKeys: 100, EmptyKeyMode: EmptyKeyBypass}
	server := httptest.NewServer(perKeyTestRouter(opts))
	defer server.Close()

	for range 5 {
		assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "").StatusCode)
	}
}

func TestPerKeyRateLimitEmptyKeySharedBucket(t *testing.T) {
	opts := PerKeyOpts{Rate: 1, Burst: 2, MaxKeys: 100, EmptyKeyMode: EmptyKeySharedBucket}
	server := httptest.NewServer(perKeyTestRouter(opts))
	defer server.Close()

	// Empty-key requests share one bucket, regardless of source.
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "").StatusCode)
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "").StatusCode)
	assertEqual(t, http.StatusTooManyRequests, doPerKeyRequest(t, server, "").StatusCode)
}

func TestPerKeyRateLimitLRUEviction(t *testing.T) {
	server := httptest.NewServer(perKeyTestRouter(PerKeyOpts{Rate: 1, Burst: 1, MaxKeys: 2}))
	defer server.Close()

	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "a").StatusCode)
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "b").StatusCode)
	// Touch "a" so "b" becomes the least recently used.
	assertEqual(t, http.StatusTooManyRequests, doPerKeyRequest(t, server, "a").StatusCode)
	// "c" evicts "b".
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "c").StatusCode)
	// "b" starts over with a fresh full bucket.
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "b").StatusCode)
	// ...which evicted "a", the new LRU entry.
	assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, "a").StatusCode)
}

func TestPerKeyRateLimitConcurrentSameKey(t *testing.T) {
	const burst = 20
	server := httptest.NewServer(perKeyTestRouter(PerKeyOpts{Rate: 1, Burst: burst, MaxKeys: 100}))
	defer server.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	// All goroutines race against the same brand-new key; exactly `burst`
	// requests may pass, never more.
	for range burst * 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if doPerKeyRequest(t, server, "hot-key").StatusCode == http.StatusOK {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assertEqual(t, burst, allowed)
}

func TestPerKeyRateLimitConcurrentManyKeys(t *testing.T) {
	server := httptest.NewServer(perKeyTestRouter(PerKeyOpts{Rate: 1, Burst: 1, MaxKeys: 1000}))
	defer server.Close()

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", i)
			assertEqual(t, http.StatusOK, doPerKeyRequest(t, server, key).StatusCode)
		}(i)
	}
	wg.Wait()
}

func TestPerKeyRateLimitZeroBurst(t *testing.T) {
	opts := PerKeyOpts{Rate: 100, Burst: 0, AllowZeroBurst: true, MaxKeys: 100}
	server := httptest.NewServer(perKeyTestRouter(opts))
	defer server.Close()

	// A zero-capacity bucket never holds a full token.
	res := doPerKeyRequest(t, server, "a")
	assertEqual(t, http.StatusTooManyRequests, res.StatusCode)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}
}

func TestPerKeyRateLimitPanics(t *testing.T) {
	cases := map[string]PerKeyOpts{
		"zero rate":              {Rate: 0, Burst: 1, MaxKeys: 1},
		"negative rate":          {Rate: -1, Burst: 1, MaxKeys: 1},
		"negative burst":         {Rate: 1, Burst: -1, MaxKeys: 1},
		"zero burst not allowed": {Rate: 1, Burst: 0, MaxKeys: 1},
		"zero max keys":          {Rate: 1, Burst: 1, MaxKeys: 0},
		"negative max keys":      {Rate: 1, Burst: 1, MaxKeys: -1},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			PerKeyRateLimit(opts)
		})
	}
}
