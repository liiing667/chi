package middleware

import (
	"container/list"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// EmptyKeyMode controls how PerKeyRateLimit treats requests whose key
// resolves to the empty string.
type EmptyKeyMode int

const (
	// EmptyKeySharedBucket routes all empty-key requests through a single
	// shared bucket, so they are rate-limited as one anonymous caller.
	EmptyKeySharedBucket EmptyKeyMode = iota
	// EmptyKeyBypass skips rate limiting entirely for empty-key requests.
	EmptyKeyBypass
)

// PerKeyOpts represents a set of options for the PerKeyRateLimit middleware.
type PerKeyOpts struct {
	// Rate is the sustained number of allowed requests per second per key.
	Rate float64
	// Burst is the maximum number of requests allowed to exceed the rate
	// momentarily, i.e. the token bucket capacity per key.
	Burst int
	// AllowZeroBurst permits Burst to be 0. A zero-capacity bucket never
	// accumulates a full token, so every request for the key is rejected.
	// Without this flag, Burst == 0 panics.
	AllowZeroBurst bool
	// MaxKeys caps the number of per-key buckets kept in memory. When the
	// cap is exceeded, the least recently used bucket is evicted.
	MaxKeys int
	// KeyFunc extracts the caller key from the request. Defaults to reading
	// the X-Api-Key header.
	KeyFunc func(r *http.Request) string
	// EmptyKeyMode controls handling of requests with an empty key.
	// Defaults to EmptyKeySharedBucket.
	EmptyKeyMode EmptyKeyMode
}

// PerKeyRateLimit is a middleware that rate-limits requests per caller key
// using a token bucket per key. Unlike Throttle, which puts a single global
// ceiling on in-flight requests, each key gets its own bucket: one caller
// exhausting its allowance does not affect others. When a request is
// rejected it receives a 429 response with a Retry-After header in whole
// seconds, rounded up.
func PerKeyRateLimit(opts PerKeyOpts) func(http.Handler) http.Handler {
	if opts.Rate <= 0 {
		panic("chi/middleware: PerKeyRateLimit expects Rate > 0")
	}
	if opts.Burst < 0 {
		panic("chi/middleware: PerKeyRateLimit expects Burst >= 0")
	}
	if opts.Burst == 0 && !opts.AllowZeroBurst {
		panic("chi/middleware: PerKeyRateLimit expects Burst > 0, or set AllowZeroBurst to permit a zero burst")
	}
	if opts.MaxKeys <= 0 {
		panic("chi/middleware: PerKeyRateLimit expects MaxKeys > 0")
	}

	keyFunc := opts.KeyFunc
	if keyFunc == nil {
		keyFunc = func(r *http.Request) string { return r.Header.Get("X-Api-Key") }
	}

	l := &perKeyLimiter{
		rate:     opts.Rate,
		burst:    float64(opts.Burst),
		maxKeys:  opts.MaxKeys,
		keyFunc:  keyFunc,
		emptyKey: opts.EmptyKeyMode,
		buckets:  make(map[string]*list.Element),
		lru:      list.New(),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := l.keyFunc(r)
			if key == "" && l.emptyKey == EmptyKeyBypass {
				next.ServeHTTP(w, r)
				return
			}

			allowed, retryAfter := l.allow(key, time.Now())
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// perKeyBucket is the token bucket state for a single key.
type perKeyBucket struct {
	key    string
	tokens float64
	last   time.Time
}

// perKeyLimiter keeps one token bucket per key, bounded by an LRU.
type perKeyLimiter struct {
	rate     float64
	burst    float64
	maxKeys  int
	keyFunc  func(r *http.Request) string
	emptyKey EmptyKeyMode

	// mu guards buckets and lru, so concurrent requests for the same new
	// key can never create two buckets that each admit traffic.
	mu      sync.Mutex
	lru     *list.List // front = most recently used, values are *perKeyBucket
	buckets map[string]*list.Element
}

// allow reports whether a request for key is admitted at time now, and if
// not, the Retry-After value in whole seconds (rounded up, at least 1).
func (l *perKeyLimiter) allow(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var b *perKeyBucket
	if elem, ok := l.buckets[key]; ok {
		b = elem.Value.(*perKeyBucket)
		l.lru.MoveToFront(elem)
	} else {
		b = &perKeyBucket{key: key, tokens: l.burst, last: now}
		l.buckets[key] = l.lru.PushFront(b)
		if l.lru.Len() > l.maxKeys {
			back := l.lru.Back()
			delete(l.buckets, back.Value.(*perKeyBucket).key)
			l.lru.Remove(back)
		}
	}

	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	retryAfter := int(math.Ceil((1 - b.tokens) / l.rate))
	if retryAfter < 1 {
		retryAfter = 1
	}
	return false, retryAfter
}
