package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

var (
	errNilSecret  = errors.New("no response nor error for token lookup")
	errNoExpire   = errors.New("no expiration time found in response")
	errNoTTL      = errors.New("no TTL found in response")
	errTokenType  = errors.New("could not assert token type")
	errBatchToken = errors.New("batch tokens cannot be reused")
)

type Lease struct {
	Token       string
	Accessor    string
	Renewable   bool
	ExpiresAt   time.Time
	NonExpiring bool
	LeaseID     string
}

func (l *Lease) IsUsable(now time.Time, safetyWindow time.Duration) bool {
	if l == nil {
		return false
	}
	if l.Token == "" {
		return false
	}
	if l.NonExpiring {
		return true
	}
	if l.ExpiresAt.IsZero() {
		return true
	}
	return now.Add(safetyWindow).Before(l.ExpiresAt)
}

func (l *Lease) Apply(client util.Client) {
	if l == nil || client == nil {
		return
	}
	if client.Token() == l.Token {
		return
	}
	client.SetToken(l.Token)
}

func LookupLease(ctx context.Context, client util.Client) (*Lease, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	token := client.AuthToken()
	if token == nil {
		return nil, fmt.Errorf("nil token interface")
	}
	resp, err := token.LookupSelfWithContext(ctx)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLookupSelf, err)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errNilSecret
	}
	lease := &Lease{Token: client.Token()}

	if id, ok := resp.Data["id"].(string); ok {
		lease.LeaseID = id
	}
	if acc, ok := resp.Data["accessor"].(string); ok {
		lease.Accessor = acc
	}

	if renewable, ok := resp.Data["renewable"].(bool); ok {
		lease.Renewable = renewable
	}

	ttlRaw, ok := resp.Data["ttl"]
	ttlSecs := int64(0)
	if ok {
		ttlNum, okNum := ttlRaw.(json.Number)
		if !okNum {
			return nil, fmt.Errorf("ttl field not json.Number")
		}
		ttlValue, convErr := ttlNum.Int64()
		if convErr != nil {
			return nil, fmt.Errorf("invalid token TTL: %v: %w", ttlRaw, convErr)
		}
		ttlSecs = ttlValue
	}

	expireRaw, ok := resp.Data["expire_time"]
	if ok {
		if expireStr, ok := expireRaw.(string); ok && expireStr != "" {
			if expireTime, parseErr := time.Parse(time.RFC3339, expireStr); parseErr == nil {
				lease.ExpiresAt = expireTime
			}
		}
	}

	if ttlSecs <= 0 {
		lease.NonExpiring = !lease.Renewable
		return lease, nil
	}

	if lease.ExpiresAt.IsZero() {
		lease.ExpiresAt = time.Now().Add(time.Duration(ttlSecs) * time.Second)
	}

	tokenTypeRaw, ok := resp.Data["type"].(string)
	if !ok {
		return nil, errTokenType
	}
	if tokenTypeRaw == "batch" {
		return nil, errBatchToken
	}

	if expireRaw == nil && lease.ExpiresAt.IsZero() {
		lease.NonExpiring = ttlSecs == 0
	}

	return lease, nil
}
