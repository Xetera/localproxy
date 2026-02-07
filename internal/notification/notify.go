package notification

import (
	"fmt"
	"log"
	"runtime"
	"strings"

	gosxnotifier "github.com/deckarep/gosx-notifier"
	"github.com/gen2brain/beeep"
)

type Notifier struct {
	appName string
}

func NewNotifier() *Notifier {
	return &Notifier{
		appName: "LocalProxy",
	}
}

// TODO: this doesn't really work
func (n *Notifier) NotifyBackend(subdomain string, isDocker bool) error {
	title := "New Proxy Backend"
	message := subdomain + ".localhost is now available"

	if runtime.GOOS == "darwin" {
		emoji := getEmoji(isDocker)
		note := gosxnotifier.NewNotification(emoji + " " + message)
		note.Title = title
		note.Sound = gosxnotifier.Glass
		log.Printf("notification: sending darwin notification for %s", subdomain)
		if err := note.Push(); err != nil {
			return fmt.Errorf("notification: gosx-notifier failed: %w", err)
		}
		log.Printf("notification: successfully sent darwin notification for %s", subdomain)
		return nil
	}

	log.Printf("notification: sending beeep notification for %s", subdomain)
	if err := beeep.Notify(title, message, ""); err != nil {
		return fmt.Errorf("notification: beeep failed: %w", err)
	}
	log.Printf("notification: successfully sent beeep notification for %s", subdomain)
	return nil
}

func getEmoji(isDocker bool) string {
	if isDocker {
		return "🐳"
	}
	return "📦"
}

func IsDockerBackend(subdomain, cwd string) bool {
	if subdomain == "" {
		return false
	}

	lowerSubdomain := strings.ToLower(subdomain)
	if strings.Contains(lowerSubdomain, "docker") || strings.Contains(lowerSubdomain, "container") {
		return true
	}

	if cwd != "" {
		lowerCwd := strings.ToLower(cwd)
		if strings.Contains(lowerCwd, "docker") || strings.Contains(lowerCwd, "/var/lib/docker") {
			return true
		}
	}

	return false
}
