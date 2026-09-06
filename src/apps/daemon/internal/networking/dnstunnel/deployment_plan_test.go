package dnstunnel

import "testing"

func TestPostRefactor232DeploymentDefaultsAndAuthority(t *testing.T) {
	plan, err := BuildDeploymentPlan(DeploymentPlanRequest{TunnelSubdomain: "t.example.com", NameserverHost: "tns.example.net", ServerIPv4: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.MTU != 1232 || plan.TunnelMode != "socks" || plan.TargetPort != 1080 || plan.ListenPort != 5300 || plan.RedirectUDPPort != 53 || plan.ServiceUser != "dnstt" {
		t.Fatalf("unexpected defaults: %+v", plan)
	}
	if len(plan.RequiredRecords) != 2 || plan.RequiredRecords[0].Type != "A" || plan.RequiredRecords[1].Type != "NS" {
		t.Fatalf("records=%+v", plan.RequiredRecords)
	}
	if !plan.RequiresRoot {
		t.Fatal("deployment should disclose root requirement")
	}
	if plan.DownloadsBinary || plan.MutatesFirewall || plan.WritesSystemd || plan.GeneratesKeys || plan.PerformsNetworkIO {
		t.Fatalf("planner gained mutation authority: %+v", plan)
	}
	if len(plan.RollbackSteps) < 3 {
		t.Fatalf("rollback plan incomplete: %v", plan.RollbackSteps)
	}
}

func TestPostRefactor232DeploymentAAAAAndSSH(t *testing.T) {
	plan, err := BuildDeploymentPlan(DeploymentPlanRequest{TunnelSubdomain: "t.example.com", NameserverHost: "tns.example.net", ServerIPv4: "1.2.3.4", ServerIPv6: "2606:4700:4700::1111", TunnelMode: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetPort != 22 || len(plan.RequiredRecords) != 3 || plan.RequiredRecords[2].Type != "AAAA" {
		t.Fatalf("unexpected ssh/AAAA plan: %+v", plan)
	}
}

func TestPostRefactor232DeploymentRejectsUnsafeInputs(t *testing.T) {
	bad := []DeploymentPlanRequest{
		{TunnelSubdomain: "t.example.com", NameserverHost: "ns.t.example.com", ServerIPv4: "1.2.3.4"},
		{TunnelSubdomain: "t.example.com", NameserverHost: "tns.example.net", ServerIPv4: "10.0.0.1"},
		{TunnelSubdomain: "t.example.com", NameserverHost: "tns.example.net", ServerIPv4: "1.2.3.4", MTU: 1410},
		{TunnelSubdomain: "t.example.com", NameserverHost: "tns.example.net", ServerIPv4: "1.2.3.4", ListenPort: 53},
	}
	for i, req := range bad {
		if _, err := BuildDeploymentPlan(req); err == nil {
			t.Fatalf("case %d unexpectedly accepted", i)
		}
	}
}
