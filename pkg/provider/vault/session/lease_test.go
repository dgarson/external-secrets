package session

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/external-secrets/external-secrets/pkg/provider/vault/fake"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

func TestLeaseIsUsable(t *testing.T) {
	now := time.Now()
	safety := time.Minute
	tests := []struct {
		name  string
		lease *Lease
		want  bool
	}{
		{"non-expiring", &Lease{Token: "tok", NonExpiring: true}, true},
		{"fresh", &Lease{Token: "tok", ExpiresAt: now.Add(2 * time.Minute)}, true},
		{"about-to-expire", &Lease{Token: "tok", ExpiresAt: now.Add(30 * time.Second)}, false},
		{"expired", &Lease{Token: "tok", ExpiresAt: now.Add(-time.Minute)}, false},
		{"missing-token", &Lease{}, false},
	}

	for _, tc := range tests {
		if got := tc.lease.IsUsable(now, safety); got != tc.want {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, got)
		}
	}
}

func TestLeaseApply(t *testing.T) {
	var setCalls int
	client := &util.VaultClient{
		SetTokenFunc: func(v string) { setCalls++ },
		TokenFunc:    func() string { return "old" },
	}

	lease := &Lease{Token: "new"}
	lease.Apply(client)
	if setCalls != 1 {
		t.Fatalf("expected SetToken to be called once, got %d", setCalls)
	}

	// Applying again with same token should not trigger SetToken
	setCalls = 0
	client = &util.VaultClient{
		SetTokenFunc: func(v string) { setCalls++ },
		TokenFunc:    func() string { return "new" },
	}
	lease.Apply(client)
	if setCalls != 0 {
		t.Fatalf("expected no SetToken call when token unchanged, got %d", setCalls)
	}
}

func TestLookupLease(t *testing.T) {
	expire := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	secret := &vault.Secret{Data: map[string]any{
		"id":          "id123",
		"accessor":    "acc456",
		"renewable":   true,
		"ttl":         json.Number("1200"),
		"expire_time": expire,
		"type":        "service",
	}}

	client := &util.VaultClient{
		TokenFunc: func() string { return "tok" },
		AuthTokenField: fake.Token{
			LookupSelfWithContextFn: func(context.Context) (*vault.Secret, error) {
				return secret, nil
			},
		},
	}

	lease, err := LookupLease(context.Background(), client)
	if err != nil {
		t.Fatalf("lookup lease: %v", err)
	}
	if lease.Token != "tok" {
		t.Fatalf("expected token 'tok', got %s", lease.Token)
	}
	if !lease.Renewable {
		t.Fatalf("expected renewable lease")
	}
	if lease.ExpiresAt.IsZero() {
		t.Fatalf("expected expiration time to be set")
	}
}

func TestLeaseApplyNilCases(t *testing.T) {
	t.Run("nil lease", func(t *testing.T) {
		var l *Lease
		client := &util.VaultClient{
			SetTokenFunc: func(v string) { t.Fatal("should not be called") },
		}
		l.Apply(client)
	})

	t.Run("nil client", func(t *testing.T) {
		l := &Lease{Token: "test"}
		l.Apply(nil)
	})
}

func TestLookupLeaseErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("nil client", func(t *testing.T) {
		_, err := LookupLease(ctx, nil)
		if err == nil {
			t.Fatal("expected error for nil client")
		}
	})

	t.Run("lookup error", func(t *testing.T) {
		client := &util.VaultClient{
			TokenFunc: func() string { return "tok" },
			AuthTokenField: fake.Token{
				LookupSelfWithContextFn: func(context.Context) (*vault.Secret, error) {
					return nil, fmt.Errorf("lookup failed")
				},
			},
		}
		_, err := LookupLease(ctx, client)
		if err == nil {
			t.Fatal("expected error from lookup")
		}
	})

	t.Run("missing ttl defaults to zero", func(t *testing.T) {
		secret := &vault.Secret{Data: map[string]any{
			"id":       "id123",
			"accessor": "acc456",
		}}
		client := &util.VaultClient{
			TokenFunc: func() string { return "tok" },
			AuthTokenField: fake.Token{
				LookupSelfWithContextFn: func(context.Context) (*vault.Secret, error) {
					return secret, nil
				},
			},
		}
		lease, err := LookupLease(ctx, client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Missing ttl should be treated as non-expiring
		if !lease.NonExpiring {
			t.Fatal("expected non-expiring lease when ttl is missing")
		}
	})

	t.Run("non-renewable with zero ttl", func(t *testing.T) {
		secret := &vault.Secret{Data: map[string]any{
			"id":        "id123",
			"accessor":  "acc456",
			"renewable": false,
			"ttl":       json.Number("0"),
		}}
		client := &util.VaultClient{
			TokenFunc: func() string { return "tok" },
			AuthTokenField: fake.Token{
				LookupSelfWithContextFn: func(context.Context) (*vault.Secret, error) {
					return secret, nil
				},
			},
		}
		lease, err := LookupLease(ctx, client)
		if err != nil {
			t.Fatalf("lookup lease: %v", err)
		}
		if !lease.NonExpiring {
			t.Fatal("expected non-expiring lease for zero ttl non-renewable")
		}
	})

	t.Run("invalid ttl format", func(t *testing.T) {
		secret := &vault.Secret{Data: map[string]any{
			"id":        "id123",
			"accessor":  "acc456",
			"renewable": true,
			"ttl":       "not-a-number",
		}}
		client := &util.VaultClient{
			TokenFunc: func() string { return "tok" },
			AuthTokenField: fake.Token{
				LookupSelfWithContextFn: func(context.Context) (*vault.Secret, error) {
					return secret, nil
				},
			},
		}
		_, err := LookupLease(ctx, client)
		if err == nil {
			t.Fatal("expected error for invalid ttl format")
		}
	})
}
