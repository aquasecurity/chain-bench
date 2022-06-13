package models

import (
	"time"
)

type Hook struct {
	CreatedAt    *time.Time
	UpdatedAt    *time.Time
	URL          *string
	ID           *int64
	Type         *string
	Name         *string
	TestURL      *string
	PingURL      *string
	LastResponse map[string]interface{}

	// Only the following fields are used when creating a hook.
	// Config is required.
	Config *HookConfig
	Events []string
	Active *bool
}

type HookConfig struct {
	Insecure_SSL *string
	URL          *string
	Secret       *string
}
