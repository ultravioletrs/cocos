package env

import "os"

// Load reads specified environment variable.
// If no value has been found, fallback is returned.
func Load(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
