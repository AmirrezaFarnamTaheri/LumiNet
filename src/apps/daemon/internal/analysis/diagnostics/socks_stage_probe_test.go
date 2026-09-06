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

package diagnostics

import (
	"bytes"
	"testing"
)

func TestBuildAndVerifySocksGreeting(t *testing.T) {
	greeting := BuildSocksGreeting()
	if !bytes.Equal(greeting, []byte{0x05, 0x01, 0x00}) {
		t.Fatalf("expected greeting {0x05, 0x01, 0x00}, got %v", greeting)
	}

	if !VerifySocksGreeting([]byte{0x05, 0x00}) {
		t.Fatalf("expected valid greeting reply to pass")
	}

	if VerifySocksGreeting([]byte{0x05, 0xff}) {
		t.Fatalf("expected rejected greeting reply to fail")
	}
}

func TestBuildAndVerifySocksConnect(t *testing.T) {
	host := "test.endpoint.com"
	port := uint16(443)

	req := BuildSocksConnect(host, port)
	if req[0] != 0x05 || req[1] != 0x01 || req[3] != 0x03 {
		t.Fatalf("invalid socks connect framing: %v", req)
	}
	if int(req[4]) != len(host) {
		t.Fatalf("length mismatch: expected %d, got %d", len(host), req[4])
	}

	// Valid IPv4 connect response: [0x05, 0x00, 0x00, 0x01]
	trailing, err := VerifySocksConnect([]byte{0x05, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("unexpected error on valid connect reply: %v", err)
	}
	if trailing != 6 {
		t.Fatalf("expected 6 trailing bytes for IPv4, got %d", trailing)
	}

	// Proxy rejected response: [0x05, 0x04, 0x00, 0x01]
	_, err = VerifySocksConnect([]byte{0x05, 0x04, 0x00, 0x01})
	if err == nil {
		t.Fatalf("expected error on rejected socks connect")
	}
}

func TestParseTraceBody(t *testing.T) {
	traceBody := `fl=42f10
h=connectivity.cloudflareclient.com
ip=198.51.100.1
ts=1713988096
visit_scheme=http
uag=Oblivion
colo=FRA
sliver=none
http=http/1.1
loc=DE
tls=off
sni=plaintext
warp=plus
`

	result := ParseTraceBody(traceBody)
	if result.Colo != "FRA" {
		t.Fatalf("expected colo FRA, got %q", result.Colo)
	}
	if result.Loc != "DE" {
		t.Fatalf("expected loc DE, got %q", result.Loc)
	}
	if result.IP != "198.51.100.1" {
		t.Fatalf("expected IP 198.51.100.1, got %q", result.IP)
	}
	if !result.IsWarpOK {
		t.Fatalf("expected warp to be marked OK for warp=plus")
	}
}

func TestAttemptLadder_Budgeting(t *testing.T) {
	if CalculateValidationBudget("turbo") != 105 {
		t.Fatalf("expected 105 for turbo")
	}
	if CalculateValidationBudget("thorough") != 360 {
		t.Fatalf("expected 360 for thorough")
	}
	if CalculateValidationBudget("stealth") != 240 {
		t.Fatalf("expected 240 for stealth")
	}
	if CalculateValidationBudget("standard") != 180 {
		t.Fatalf("expected 180 for standard")
	}
}

func TestAttemptLadder_LadderStages(t *testing.T) {
	// Standard with fast connect enabled -> 2 stages
	ladder := BuildAttemptLadder("standard", "m1", true, false)
	if len(ladder) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(ladder))
	}
	if ladder[0].Label != "fast" || ladder[0].BudgetSec != 30 {
		t.Fatalf("expected fast stage with 30s budget, got %+v", ladder[0])
	}
	if ladder[1].Label != "configured" || ladder[1].BudgetSec != 180 {
		t.Fatalf("expected configured stage with 180s budget, got %+v", ladder[1])
	}

	// Psiphon enabled -> 1 stage
	psiphonLadder := BuildAttemptLadder("standard", "m1", true, true)
	if len(psiphonLadder) != 1 {
		t.Fatalf("expected 1 stage for psiphon, got %d", len(psiphonLadder))
	}
}
