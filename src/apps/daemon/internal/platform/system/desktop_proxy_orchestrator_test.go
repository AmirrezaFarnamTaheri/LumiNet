// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package system

import (
	"testing"
)

func TestParseDesktopRoutingRules(t *testing.T) {
	raw := "domain:google.com,!domain:special.org,*domain:*.cdn.net,ip:10.0.0.1,range:192.168.*,app:firefox"
	rules := ParseDesktopRoutingRules(raw)

	if len(rules) != 5 {
		t.Fatalf("expected 5 rules (excluding app: rule), got %d", len(rules))
	}

	if rules[0].Type != "domain" || rules[0].Value != "google.com" || rules[0].ForceProxy {
		t.Errorf("rule 0 mismatch: %+v", rules[0])
	}

	if rules[1].Type != "domain" || rules[1].Value != "special.org" || !rules[1].ForceProxy {
		t.Errorf("rule 1 mismatch: %+v", rules[1])
	}

	if rules[2].Type != "domain" || !rules[2].IsWildcard {
		t.Errorf("rule 2 mismatch: %+v", rules[2])
	}

	if rules[3].Type != "ip" || rules[3].Value != "10.0.0.1" {
		t.Errorf("rule 3 mismatch: %+v", rules[3])
	}

	if rules[4].Type != "range" || !rules[4].IsWildcard {
		t.Errorf("rule 4 mismatch: %+v", rules[4])
	}
}

func TestNetStatsSampler(t *testing.T) {
	sampler := NewNetStatsSampler()

	snap1 := sampler.RecordSample(1000, 5000)
	if snap1.BytesSent != 1000 || snap1.BytesReceived != 5000 {
		t.Errorf("unexpected initial sample: %+v", snap1)
	}

	snap2 := sampler.RecordSample(2500, 10000)
	if snap2.BytesSent != 1500 || snap2.BytesReceived != 5000 {
		t.Errorf("unexpected delta in sample 2: %+v", snap2)
	}

	if snap2.TotalSent != 2500 || snap2.TotalReceived != 10000 {
		t.Errorf("unexpected totals: sent %d, recv %d", snap2.TotalSent, snap2.TotalReceived)
	}
}

func TestResolveColoLocation(t *testing.T) {
	fra := ResolveColoLocation("FRA")
	if fra.CountryCode != "DE" || fra.FlagEmoji != "🇩🇪" {
		t.Errorf("expected Germany for FRA, got %+v", fra)
	}

	lhr := ResolveColoLocation("lhr") // test lowercase
	if lhr.CountryCode != "GB" || lhr.FlagEmoji != "🇬🇧" {
		t.Errorf("expected UK for LHR, got %+v", lhr)
	}

	unknown := ResolveColoLocation("XYZ")
	if unknown.CountryCode != "XX" || unknown.FlagEmoji != "🌐" {
		t.Errorf("expected global edge for XYZ, got %+v", unknown)
	}
}

func TestResolveIspName(t *testing.T) {
	if !testing.Short() {
		mci := ResolveIspName(197207)
		if mci != "MCI (Mobile Telecommunication Co of Iran)" {
			t.Errorf("expected MCI, got %s", mci)
		}

		cf := ResolveIspName(13335)
		if cf != "Cloudflare, Inc." {
			t.Errorf("expected Cloudflare, got %s", cf)
		}

		unknown := ResolveIspName(999999)
		if unknown != "AS999999" {
			t.Errorf("expected AS999999, got %s", unknown)
		}
	}
}
