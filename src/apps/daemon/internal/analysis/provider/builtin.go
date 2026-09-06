package provider

// BuiltinCorpus is the provenance-tagged fallback corpus shipped with the
// daemon. It is intentionally data-only; network refresh is not implied.
func BuiltinCorpus() Corpus {
	return Corpus{SchemaVersion: 1, CorpusID: "builtin-provider-prefixes-v1", GeneratorVersion: "manual-builtin-provider-prefixes-v1", GeneratedAt: "2026-05-24T00:00:00Z", FetchedAt: "2026-05-24T00:00:00Z", StaleAfter: "2026-06-23T00:00:00Z", Checksum: "manual:builtin-provider-prefixes-v1", Providers: []Manifest{
		{ProviderID: "cloudflare", DisplayName: "Cloudflare", SourceURL: "builtin://provider_observer", SourceLicense: "manual-builtin", SourceKind: "manual_fixture", Confidence: "medium", Priority: 100, IPv4Prefixes: []string{"104.16.0.0/12", "172.64.0.0/13"}, IPv6Prefixes: []string{"2606:4700::/32"}},
		{ProviderID: "fastly", DisplayName: "Fastly", SourceURL: "builtin://provider_observer", SourceLicense: "manual-builtin", SourceKind: "manual_fixture", Confidence: "medium", Priority: 90, IPv4Prefixes: []string{"151.101.0.0/16"}, IPv6Prefixes: []string{"2a04:4e42::/32"}},
		{ProviderID: "cloudfront", DisplayName: "Amazon CloudFront", SourceURL: "builtin://provider_observer", SourceLicense: "manual-builtin", SourceKind: "manual_fixture", Confidence: "medium", Priority: 80, IPv4Prefixes: []string{"13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "54.230.0.0/16"}},
		{ProviderID: "akamai", DisplayName: "Akamai", SourceURL: "builtin://provider_observer", SourceLicense: "manual-builtin", SourceKind: "manual_fixture", Confidence: "medium", Priority: 70, IPv4Prefixes: []string{"23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13"}, IPv6Prefixes: []string{"2a02:26f0::/32"}},
	}}
}
