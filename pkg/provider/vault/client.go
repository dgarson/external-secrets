/*
Copyright © 2025 ESO Maintainer Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/go-logr/logr"
	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
	"github.com/external-secrets/external-secrets/pkg/utils"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

var _ esv1.SecretsClient = &secretsClient{}

type secretsClient struct {
	kube         kclient.Client
	store        *esv1.VaultProvider
	log          logr.Logger
	corev1       typedcorev1.CoreV1Interface
	client       util.Client
	auth         util.Auth
	logical      util.Logical
	token        util.Token
	namespace    string
	storeKind    string
	configDigest string
}

// buildVaultConfig creates a Vault SDK configuration from authContext.
// This is a standalone function that doesn't depend on secretsClient,
// making it usable during initial client creation.
func buildVaultConfig(ctx context.Context, authCtx *authContext) (*vault.Config, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = authCtx.spec.Server

	if len(authCtx.spec.CABundle) != 0 || authCtx.spec.CAProvider != nil {
		caCertPool := x509.NewCertPool()
		ca, err := utils.FetchCACertFromSource(ctx, utils.CreateCertOpts{
			CABundle:   authCtx.spec.CABundle,
			CAProvider: authCtx.spec.CAProvider,
			StoreKind:  authCtx.storeKind,
			Namespace:  authCtx.namespace,
			Client:     authCtx.kube,
		})
		if err != nil {
			return nil, err
		}
		ok := caCertPool.AppendCertsFromPEM(ca)
		if !ok {
			return nil, fmt.Errorf(errVaultCert, errors.New("failed to parse certificates from CertPool"))
		}

		if transport, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.RootCAs = caCertPool
		}
	}

	err := configureClientTLS(ctx, authCtx, cfg)
	if err != nil {
		return nil, err
	}

	// If either read-after-write consistency feature is enabled, enable ReadYourWrites
	cfg.ReadYourWrites = authCtx.spec.ReadYourWrites || authCtx.spec.ForwardInconsistent

	return cfg, nil
}

// configureClientTLS configures TLS client certificates on the Vault config.
// This is a standalone function that accepts authContext for flexibility.
func configureClientTLS(ctx context.Context, authCtx *authContext, cfg *vault.Config) error {
	clientTLS := authCtx.spec.ClientTLS
	if clientTLS.CertSecretRef != nil && clientTLS.KeySecretRef != nil {
		if clientTLS.KeySecretRef.Key == "" {
			clientTLS.KeySecretRef.Key = corev1.TLSPrivateKeyKey
		}
		clientKey, err := resolvers.SecretKeyRef(ctx, authCtx.kube, authCtx.storeKind, authCtx.namespace, clientTLS.KeySecretRef)
		if err != nil {
			return err
		}

		if clientTLS.CertSecretRef.Key == "" {
			clientTLS.CertSecretRef.Key = corev1.TLSCertKey
		}
		clientCert, err := resolvers.SecretKeyRef(ctx, authCtx.kube, authCtx.storeKind, authCtx.namespace, clientTLS.CertSecretRef)
		if err != nil {
			return err
		}

		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return fmt.Errorf(errClientTLSAuth, err)
		}

		if transport, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
			transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}
	return nil
}

// computeVaultConfigDigest computes a hash digest of the Vault configuration.
// This is used to detect configuration changes and invalidate cached clients.
// This is a standalone function that accepts authContext for flexibility.
func computeVaultConfigDigest(ctx context.Context, authCtx *authContext, store esv1.GenericStore) (string, error) {
	hasher := sha256.New()
	writePart := func(parts ...string) {
		for _, p := range parts {
			_, _ = hasher.Write([]byte(p))
			_, _ = hasher.Write([]byte{0})
		}
	}

	if store != nil {
		writePart("store-gen", fmt.Sprintf("%d", store.GetGeneration()))
	}

	if authCtx.spec.Namespace != nil {
		writePart("vault-namespace", *authCtx.spec.Namespace)
	}

	if authCtx.spec.ReadYourWrites {
		writePart("read-your-writes", "true")
	}

	if authCtx.spec.ForwardInconsistent {
		writePart("forward-inconsistent", "true")
	}

	if len(authCtx.spec.Headers) > 0 {
		keys := make([]string, 0, len(authCtx.spec.Headers))
		for k := range authCtx.spec.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			writePart("header", k, authCtx.spec.Headers[k])
		}
	}

	if len(authCtx.spec.CABundle) > 0 {
		writePart("ca-bundle-inline")
		_, _ = hasher.Write(authCtx.spec.CABundle)
		_, _ = hasher.Write([]byte{0})
	}

	if authCtx.spec.CAProvider != nil {
		cp := authCtx.spec.CAProvider
		ns := authCtx.namespace
		if cp.Namespace != nil {
			ns = *cp.Namespace
		}

		key := kclient.ObjectKey{
			Name:      cp.Name,
			Namespace: ns,
		}

		switch cp.Type {
		case esv1.CAProviderTypeSecret:
			secret := &corev1.Secret{}
			if err := authCtx.kube.Get(ctx, key, secret); err != nil {
				return "", err
			}
			writePart("ca-secret", fmt.Sprintf("%s/%s", key.Namespace, key.Name), fmt.Sprintf("v%s", secret.ResourceVersion))
		case esv1.CAProviderTypeConfigMap:
			configMap := &corev1.ConfigMap{}
			if err := authCtx.kube.Get(ctx, key, configMap); err != nil {
				return "", err
			}
			writePart("ca-configmap", fmt.Sprintf("%s/%s", key.Namespace, key.Name), fmt.Sprintf("v%s", configMap.ResourceVersion))
		default:
			return "", fmt.Errorf("unsupported CA provider type: %s", cp.Type)
		}
	}

	clientTLS := authCtx.spec.ClientTLS
	if clientTLS.CertSecretRef != nil {
		ns := authCtx.namespace
		if clientTLS.CertSecretRef.Namespace != nil {
			ns = *clientTLS.CertSecretRef.Namespace
		}
		if ns == "" {
			return "", fmt.Errorf("missing namespace for client TLS cert secret %q", clientTLS.CertSecretRef.Name)
		}

		secret := &corev1.Secret{}
		if err := authCtx.kube.Get(ctx, kclient.ObjectKey{Namespace: ns, Name: clientTLS.CertSecretRef.Name}, secret); err != nil {
			return "", err
		}
		writePart("tls-cert", fmt.Sprintf("%s/%s", ns, clientTLS.CertSecretRef.Name), fmt.Sprintf("v%s", secret.ResourceVersion))
	}

	if clientTLS.KeySecretRef != nil {
		ns := authCtx.namespace
		if clientTLS.KeySecretRef.Namespace != nil {
			ns = *clientTLS.KeySecretRef.Namespace
		}
		if ns == "" {
			return "", fmt.Errorf("missing namespace for client TLS key secret %q", clientTLS.KeySecretRef.Name)
		}

		secret := &corev1.Secret{}
		if err := authCtx.kube.Get(ctx, kclient.ObjectKey{Namespace: ns, Name: clientTLS.KeySecretRef.Name}, secret); err != nil {
			return "", err
		}
		writePart("tls-key", fmt.Sprintf("%s/%s", ns, clientTLS.KeySecretRef.Name), fmt.Sprintf("v%s", secret.ResourceVersion))
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// newConfig is a wrapper around buildVaultConfig for backward compatibility.
// It delegates to the standalone buildVaultConfig function.
func (sc *secretsClient) newConfig(ctx context.Context) (*vault.Config, error) {
	authCtx := newAuthContext(sc.store, sc.kube, sc.corev1, sc.namespace, sc.storeKind)
	return buildVaultConfig(ctx, authCtx)
}

// computeConfigDigest is a wrapper around computeVaultConfigDigest for backward compatibility.
// It delegates to the standalone computeVaultConfigDigest function.
func (sc *secretsClient) computeConfigDigest(ctx context.Context, store esv1.GenericStore) (string, error) {
	authCtx := newAuthContext(sc.store, sc.kube, sc.corev1, sc.namespace, sc.storeKind)
	return computeVaultConfigDigest(ctx, authCtx, store)
}

func (sc *secretsClient) Close(ctx context.Context) error {
	if enableVaultClientPooling {
		if _, ok := sc.client.(*pooledVaultClient); ok {
			// Pooled clients are kept alive across reconciliations; eviction handles revocation.
			return nil
		}
	}

	// Revoke the token if we have one set, it wasn't sourced from a TokenSecretRef,
	// and token caching isn't enabled
	if !enableCache && sc.client.Token() != "" && sc.store.Auth != nil && sc.store.Auth.TokenSecretRef == nil {
		err := revokeTokenIfValid(ctx, sc.client)
		if err != nil {
			return err
		}
	}
	return nil
}
