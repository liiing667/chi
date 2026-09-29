package middleware

import (
	"container/list"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// EmptyKeyPolicy controls how requests without a key are treated by
// PerKeyRateLimit.
type EmptyKeyPolicy int

const (
	// EmptyKeyShared makes all requests with an empty key share a single
	// default bucket. This is the default behavior.
	EmptyKeyShared EmptyKeyPolicy = iota
	// EmptyKeyBypass lets requests with an empty key skip rate limiting
	// entirely.
	EmptyKeyBypass
)

// PerKeyOpts represents a set of options for the PerKeyRateLimit middleware.
type PerKeyOpts struct {
	// Rate is the number of tokens refilled per second for each key.
	// It must be greater than zero.
	Rate float64

	// Burst is the maximum number of tokens a bucket can hold, i.e. the
	// maximum number of requests a key can fire at once. It must be
	// greater than zero unless AllowZeroBurst is set.
	Burst int

	// AllowZeroBurst permits Burst to be zero, in which case every bucket
	// effectively holds a single token and no bursting beyond Rate is
	// possible.
	AllowZeroBurst bool

	// MaxKeys is the maximum number of per-key buckets kept in memory.
	// Once the limit is reached, the least recently used bucket is
	// evicted to make room for new keys. It must be greater than zero.
	MaxKeys int

	// KeyFunc extracts the rate-limiting key from a request.
	// Defaults to reading the X-Api-Key header.
	KeyFunc func(r *http.Request) string

	// EmptyKeyPolicy controls how requests with an empty key are
	// handled. Defaults to EmptyKeyShared.
	EmptyKeyPolicy EmptyKeyPolicy
}

// PerKeyRateLimit is a middleware that rate-limits requests per key using a
// token bucket per key. Unlike Throttle, which puts a single ceiling on all
// traffic, each key (by default the X-Api-Key header) gets its own bucket, so
// one caller exhausting its allowance does not affect others.
//
// The number of buckets is bounded by PerKeyOpts.MaxKeys; least recently used
// buckets are evicted when the limit is reached. Requests that exceed their
// allowance are rejected with 429 Too Many Requests and a Retry-After header
// rounded up to whole seconds.
func PerKeyRateLimit(opts PerKeyOpts) func(http.Handler) http.Handler {
	if opts.Rate <= 0 {
		panic("chi/middleware: PerKeyRateLimit expects rate > 0")
	}
	if opts.Burst < 0 || (opts.Burst == 0 && !opts.AllowZeroBurst) {
		panic("chi/middleware: PerKeyRateLimit expects burst > 0, or burst == 0 with AllowZeroBurst")
	}
	if opts.MaxKeys < 1 {
		panic("chi/middleware: PerKeyRateLimit expects maxKeys > 0")
	}
	if opts.KeyFunc == nil {
		opts.KeyFunc = func(r *http.Request) string {
			return r.Header.Get("X-Api-Key")
		}
	}

	burst := opts.Burst
	if burst == 0 {
		burst = 1
	}

	limiter := &perKeyLimiter{
		rate:    opts.Rate,
		burst:   float64(burst),
		maxKeys: opts.MaxKeys,
		buckets: make(map[string]*list.Element),
		lru:     list.New(),
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			key := opts.KeyFunc(r)

			if key == "" && opts.EmptyKeyPolicy == EmptyKeyBypass {
				next.ServeHTTP(w, r)
				return
			}

			allowed, retryAfter := limiter.allow(key, time.Now())
			if !allowed {
				seconds := int(math.Ceil(retryAfter.Seconds()))
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

// keyBucket is a lazily refilled token bucket for a single key.
type keyBucket struct {
	key    string
	tokens float64
	last   time.Time
}

// perKeyLimiter keeps one token bucket per key, bounded by an LRU.
// A single mutex guards bucket lookup, creation, eviction and token
// accounting, so concurrent requests for the same new key can never
// end up with two buckets that each let traffic through.
type perKeyLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	maxKeys int
	buckets map[string]*list.Element // key -> *list.Element holding *keyBucket
	lru     *list.List               // front is most recently used
	empty   *keyBucket               // shared bucket for empty keys, not counted against maxKeys
}

// allow reports whether a request for key may proceed, and if not, how long
// the caller should wait before retrying.
func (l *perKeyLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var b *keyBucket
	if key == "" {
		if l.empty == nil {
			l.empty = &keyBucket{tokens: l.burst, last: now}
		}
		b = l.empty
	} else if el, ok := l.buckets[key]; ok {
		l.lru.MoveToFront(el)
		b = el.Value.(*keyBucket)
	} else {
		if len(l.buckets) >= l.maxKeys {
			oldest := l.lru.Back()
			delete(l.buckets, oldest.Value.(*keyBucket).key)
			l.lru.Remove(oldest)
		}
		b = &keyBucket{key: key, tokens: l.burst, last: now}
		l.buckets[key] = l.lru.PushFront(b)
	}

	// Lazy refill based on elapsed time.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}
