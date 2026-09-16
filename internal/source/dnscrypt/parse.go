package dnscrypt

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"doh-finder/internal/pkg/ds"

	dnsstamps "github.com/jedisct1/go-dnsstamps"
)

// Every stamp is a separate endpoint, including multiple stamps under one heading.
func parse(body []byte) ([]ds.Resolver, error) {
	resolvers := make([]ds.Resolver, 0)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maxDownload)
	name := ""
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "## ") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			continue
		}
		if !strings.HasPrefix(line, "sdns://") {
			continue
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(line, "sdns://"))
		if err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("line %d: invalid DNS stamp encoding", lineNumber)
		}
		if raw[0] != byte(dnsstamps.StampProtoTypeDoH) {
			continue
		}
		if name == "" {
			return nil, fmt.Errorf("line %d: DoH stamp has no resolver heading", lineNumber)
		}
		resolver, err := decode(name, line)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", lineNumber, name, err)
		}
		resolvers = append(resolvers, resolver)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read resolver list: %w", err)
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("source contains no DoH stamps")
	}
	return resolvers, nil
}

func decode(name, text string) (ds.Resolver, error) {
	stamp, err := dnsstamps.NewServerStampFromString(text)
	if err != nil {
		return ds.Resolver{}, fmt.Errorf("decode DoH stamp: %w", err)
	}
	// Preserve the exact authority and URI path, including ports and escaped paths.
	dohURL := "https://" + stamp.ProviderName + stamp.Path
	u, err := url.Parse(dohURL)
	if err != nil {
		return ds.Resolver{}, fmt.Errorf("parse DoH URL: %w", err)
	}
	if stamp.ProviderName == "" || strings.ContainsAny(stamp.ProviderName, "/?#@ \\") ||
		!strings.HasPrefix(stamp.Path, "/") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return ds.Resolver{}, fmt.Errorf("invalid DoH authority or path")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return ds.Resolver{}, fmt.Errorf("invalid DoH port")
		}
	}
	var ip *string
	if stamp.ServerAddrStr != "" {
		value, err := normalizeIP(stamp.ServerAddrStr)
		if err != nil {
			return ds.Resolver{}, fmt.Errorf("invalid endpoint IP: %w", err)
		}
		ip = &value
	}
	hashes := make([]string, 0, len(stamp.Hashes))
	for _, hash := range stamp.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}
	bootstrapDNS := make([]string, 0, len(stamp.BootstrapIPs))
	for _, address := range stamp.BootstrapIPs {
		value, err := normalizeIP(address)
		if err != nil {
			return ds.Resolver{}, fmt.Errorf("invalid bootstrap DNS IP: %w", err)
		}
		bootstrapDNS = append(bootstrapDNS, value)
	}
	return ds.Resolver{
		Name: name, IP: ip, DoHURL: dohURL, Stamp: text,
		Properties: ds.Properties{
			DNSSEC:   stamp.Props&dnsstamps.ServerInformalPropertyDNSSEC != 0,
			NoLog:    stamp.Props&dnsstamps.ServerInformalPropertyNoLog != 0,
			NoFilter: stamp.Props&dnsstamps.ServerInformalPropertyNoFilter != 0,
		},
		Hashes: hashes, BootstrapDNS: bootstrapDNS,
	}, nil
}

func normalizeIP(value string) (string, error) {
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	return address.String(), nil
}
