package trapdoor

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

var expungerLock = false

func expunger(interval caddy.Duration, logger *zap.Logger) {
	if expungerLock {
		return
	}

	expungerLock = true
	defer func() {
		expungerLock = false
	}()

	for {
		<-time.After(time.Duration(interval))

		toExpunge := make([]string, 0, 16)

		// collect IPs to expunge
		bannedIPsMutex.RLock()
		for ip, expiration := range bannedIPs {
			if expiration.Compare(time.Now()) != 1 {
				toExpunge = append(toExpunge, ip)
			}
		}
		bannedIPsMutex.RUnlock()

		if len(toExpunge) == 0 {
			continue
		}

		logger.Sugar().Debugf("toExpunge: %+v", toExpunge)

		// expunge IPs
		bannedIPsMutex.Lock()
		for _, ip := range toExpunge {
			delete(bannedIPs, ip)
		}
		bannedIPsMutex.Unlock()
	}
}
