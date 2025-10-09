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

var _ esv1.SecretsClient = &client{}

type client struct {
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

func (c *client) newConfig(ctx context.Context) (*vault.Config, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = c.store.Server

	if len(c.store.CABundle) != 0 || c.store.CAProvider != nil {
		caCertPool := x509.NewCertPool()
		ca, err := utils.FetchCACertFromSource(ctx, utils.CreateCertOpts{
			CABundle:   c.store.CABundle,
			CAProvider: c.store.CAProvider,
			StoreKind:  c.storeKind,
			Namespace:  c.namespace,
			Client:     c.kube,
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

	err := c.configureClientTLS(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// If either read-after-write consistency feature is enabled, enable ReadYourWrites
	cfg.ReadYourWrites = c.store.ReadYourWrites || c.store.ForwardInconsistent

	return cfg, nil
}

func (c *client) configureClientTLS(ctx context.Context, cfg *vault.Config) error {
	clientTLS := c.store.ClientTLS
	if clientTLS.CertSecretRef != nil && clientTLS.KeySecretRef != nil {
		if clientTLS.KeySecretRef.Key == "" {
			clientTLS.KeySecretRef.Key = corev1.TLSPrivateKeyKey
		}
		clientKey, err := resolvers.SecretKeyRef(ctx, c.kube, c.storeKind, c.namespace, clientTLS.KeySecretRef)
		if err != nil {
			return err
		}

		if clientTLS.CertSecretRef.Key == "" {
			clientTLS.CertSecretRef.Key = corev1.TLSCertKey
		}
		clientCert, err := resolvers.SecretKeyRef(ctx, c.kube, c.storeKind, c.namespace, clientTLS.CertSecretRef)
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

func (c *client) computeConfigDigest(ctx context.Context, store esv1.GenericStore) (string, error) {
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

	if c.store.Namespace != nil {
		writePart("vault-namespace", *c.store.Namespace)
	}

	if c.store.ReadYourWrites {
		writePart("read-your-writes", "true")
	}

	if c.store.ForwardInconsistent {
		writePart("forward-inconsistent", "true")
	}

	if len(c.store.Headers) > 0 {
		keys := make([]string, 0, len(c.store.Headers))
		for k := range c.store.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			writePart("header", k, c.store.Headers[k])
		}
	}

	if len(c.store.CABundle) > 0 {
		writePart("ca-bundle-inline")
		_, _ = hasher.Write(c.store.CABundle)
		_, _ = hasher.Write([]byte{0})
	}

	if c.store.CAProvider != nil {
		cp := c.store.CAProvider
		ns := c.namespace
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
			if err := c.kube.Get(ctx, key, secret); err != nil {
				return "", err
			}
			writePart("ca-secret", fmt.Sprintf("%s/%s", key.Namespace, key.Name), fmt.Sprintf("v%s", secret.ResourceVersion))
		case esv1.CAProviderTypeConfigMap:
			configMap := &corev1.ConfigMap{}
			if err := c.kube.Get(ctx, key, configMap); err != nil {
				return "", err
			}
			writePart("ca-configmap", fmt.Sprintf("%s/%s", key.Namespace, key.Name), fmt.Sprintf("v%s", configMap.ResourceVersion))
		default:
			return "", fmt.Errorf("unsupported CA provider type: %s", cp.Type)
		}
	}

	clientTLS := c.store.ClientTLS
	if clientTLS.CertSecretRef != nil {
		ns := c.namespace
		if clientTLS.CertSecretRef.Namespace != nil {
			ns = *clientTLS.CertSecretRef.Namespace
		}
		if ns == "" {
			return "", fmt.Errorf("missing namespace for client TLS cert secret %q", clientTLS.CertSecretRef.Name)
		}

		secret := &corev1.Secret{}
		if err := c.kube.Get(ctx, kclient.ObjectKey{Namespace: ns, Name: clientTLS.CertSecretRef.Name}, secret); err != nil {
			return "", err
		}
		writePart("tls-cert", fmt.Sprintf("%s/%s", ns, clientTLS.CertSecretRef.Name), fmt.Sprintf("v%s", secret.ResourceVersion))
	}

	if clientTLS.KeySecretRef != nil {
		ns := c.namespace
		if clientTLS.KeySecretRef.Namespace != nil {
			ns = *clientTLS.KeySecretRef.Namespace
		}
		if ns == "" {
			return "", fmt.Errorf("missing namespace for client TLS key secret %q", clientTLS.KeySecretRef.Name)
		}

		secret := &corev1.Secret{}
		if err := c.kube.Get(ctx, kclient.ObjectKey{Namespace: ns, Name: clientTLS.KeySecretRef.Name}, secret); err != nil {
			return "", err
		}
		writePart("tls-key", fmt.Sprintf("%s/%s", ns, clientTLS.KeySecretRef.Name), fmt.Sprintf("v%s", secret.ResourceVersion))
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (c *client) Close(ctx context.Context) error {
	if enableVaultClientPooling {
		if _, ok := c.client.(*pooledVaultClient); ok {
			// Pooled clients are kept alive across reconciliations; eviction handles revocation.
			return nil
		}
	}

	// Revoke the token if we have one set, it wasn't sourced from a TokenSecretRef,
	// and token caching isn't enabled
	if !enableCache && c.client.Token() != "" && c.store.Auth != nil && c.store.Auth.TokenSecretRef == nil {
		err := revokeTokenIfValid(ctx, c.client)
		if err != nil {
			return err
		}
	}
	return nil
}
