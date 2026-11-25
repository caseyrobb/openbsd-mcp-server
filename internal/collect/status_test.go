package collect

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

func TestSubsystemTablesMatchRegistry(t *testing.T) {
	all := basecmd.Enabled{basecmd.FeaturePF: true, basecmd.FeatureUnbound: true, basecmd.FeatureBGP: true}
	for _, s := range Subsystems {
		seen := map[string]bool{}
		for _, v := range s.Views {
			if seen[v.Name] {
				t.Errorf("%s: duplicate view %q", s.Name, v.Name)
			}
			seen[v.Name] = true
			spec, err := basecmd.Lookup(v.ID, all)
			if err != nil {
				t.Errorf("%s/%s: %v", s.Name, v.Name, err)
				continue
			}
			// A view may only run commands of its own subsystem's feature.
			if spec.Feature != s.Feature {
				t.Errorf("%s/%s runs %s (feature %q)", s.Name, v.Name, v.ID, spec.Feature)
			}
			if _, err := basecmd.Lookup(v.ID, nil); err == nil {
				t.Errorf("%s/%s is runnable with no features enabled", s.Name, v.Name)
			}
		}
	}
}

func TestStatusRunsMappedCommandAndRedacts(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{
		basecmd.BGPNeighbors: {Stdout: "BGP neighbor is 192.0.2.1, remote AS 64512\n  tcp md5sig password s3cret\n"},
	}}
	got, err := Status(context.Background(), f, BGP, "neighbors")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls, []basecmd.ID{basecmd.BGPNeighbors}) {
		t.Errorf("calls = %v", f.calls)
	}
	if strings.Contains(got.Output, "s3cret") || got.Redactions != 1 {
		t.Errorf("not redacted: %+v", got)
	}
	if got.Command != "/usr/sbin/bgpctl -s /var/run/bgpd.rsock show neighbor" || got.View != "neighbors" || got.Subsystem != "bgp" {
		t.Errorf("got %+v", got)
	}
}

func TestStatusUnknownViewRunsNothing(t *testing.T) {
	f := &fakeRunner{}
	for _, v := range []string{"", "states", "flush", "rules; reboot", "../info", "INFO"} {
		if _, err := Status(context.Background(), f, PF, v); !errors.Is(err, ErrUnknownView) {
			t.Errorf("view %q: err = %v", v, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("commands ran for unknown views: %v", f.calls)
	}
}

func TestStatusUnboundStatsNeverResets(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{basecmd.UnboundStats: {Stdout: "total.num.queries=42\n"}}}
	got, err := Status(context.Background(), f, Unbound, "stats")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got.Command, "unbound-control stats_noreset") {
		t.Fatalf("stats view runs %q", got.Command)
	}
}

func TestStatusFailureIncludesStderrAndHint(t *testing.T) {
	f := &fakeRunner{
		out:  map[basecmd.ID]execx.Result{basecmd.PfRules: {Stderr: "doas: Operation not permitted\n"}},
		fail: map[basecmd.ID]bool{basecmd.PfRules: true},
	}
	_, err := Status(context.Background(), f, PF, "rules")
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"non-zero exit", "doas: Operation not permitted", "-print-doas"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestStatusCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Status(ctx, &fakeRunner{}, PF, "info"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
