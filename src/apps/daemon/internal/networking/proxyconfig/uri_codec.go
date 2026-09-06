package proxyconfig

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrInvalidProxyURI = errors.New("invalid proxy uri")
)

type CanonicalProxyNode struct {
	Protocol       string
	UUIDOrPassword string
	Address        string
	Port           uint16
	Remark         string
	Params         map[string]string
}

type ProxyUriCodec struct{}

func (c *ProxyUriCodec) Parse(rawURI string) (*CanonicalProxyNode, error) {
	trimmed := strings.TrimSpace(rawURI)
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, ErrInvalidProxyURI
	}

	protocol := strings.ToLower(u.Scheme)
	remark := u.Fragment

	credentials := ""
	if u.User != nil {
		credentials = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			credentials = credentials + ":" + pass
		}
	}

	host := u.Hostname()
	portStr := u.Port()
	portVal, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		portVal = 443
	}

	params := make(map[string]string)
	q := u.Query()
	for k, v := range q {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	return &CanonicalProxyNode{
		Protocol:       protocol,
		UUIDOrPassword: credentials,
		Address:        host,
		Port:           uint16(portVal),
		Remark:         remark,
		Params:         params,
	}, nil
}

func (c *ProxyUriCodec) Serialize(node *CanonicalProxyNode) string {
	keys := make([]string, 0, len(node.Params))
	for k := range node.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var qParts []string
	for _, k := range keys {
		qParts = append(qParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(node.Params[k])))
	}

	qStr := ""
	if len(qParts) > 0 {
		qStr = "?" + strings.Join(qParts, "&")
	}

	remStr := ""
	if node.Remark != "" {
		remStr = "#" + node.Remark
	}

	return fmt.Sprintf("%s://%s@%s:%d%s%s",
		node.Protocol, node.UUIDOrPassword, node.Address, node.Port, qStr, remStr)
}
