package procevents

import (
	"os/user"
	"strconv"
	"sync"
	"sync/atomic"
)

// maxCachedUsers bounds the cache of user names. A host has far fewer users
// than this; a container host that maps many numeric IDs could reach it, and
// the cache is then simply started again.
const maxCachedUsers = 1024

// userCache resolves numeric user IDs to names the way the polling collector
// does (os/user), remembering the answers: a lookup can mean reading
// /etc/passwd or asking a directory service, which is too slow to repeat for
// every process.
type userCache struct {
	mu     sync.Mutex
	names  map[uint32]string
	lookup func(uid uint32) string

	size   atomic.Int64
	resets atomic.Uint64
}

func newUserCache() *userCache {
	return &userCache{
		names: make(map[uint32]string),
		lookup: func(uid uint32) string {
			found, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
			if err != nil {
				// The polling collector reports no user name for
				// an ID nothing knows, and so does this.
				return ""
			}
			return found.Username
		},
	}
}

func (c *userCache) name(uid uint32) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if name, cached := c.names[uid]; cached {
		return name
	}

	if len(c.names) >= maxCachedUsers {
		c.names = make(map[uint32]string)
		c.resets.Add(1)
	}

	name := c.lookup(uid)
	c.names[uid] = name
	c.size.Store(int64(len(c.names)))

	return name
}
