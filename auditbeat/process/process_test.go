package process

import (
	"os/user"
	"testing"
	"time"

	"github.com/elastic/beats/v7/auditbeat/core"
	"github.com/elastic/beats/v7/auditbeat/helper/hasher"
	abtest "github.com/elastic/beats/v7/auditbeat/testing"
	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	"github.com/elastic/go-sysinfo/types"
)

func TestData(t *testing.T) {
	defer abtest.SetupDataDir(t)()

	f := mbtest.NewReportingMetricSetV2(t, getConfig())

	// Set lastSate and add test process to cache so it will be reported as stopped.
	f.(*MetricSet).lastState = time.Now()
	p := testProcess()
	f.(*MetricSet).cache.DiffAndUpdateCache(convertToCacheable([]*Process{p}))

	events, errs := mbtest.ReportingFetchV2(f)
	if len(errs) > 0 {
		t.Fatalf("received error: %+v", errs[0])
	}

	if len(events) == 0 {
		t.Fatal("no events were generated")
	}

	fullEvent := mbtest.StandardizeEvent(f, events[len(events)-1], core.AddDatasetToEvent)
	mbtest.WriteEventToDataJSON(t, fullEvent, "")
}

func getConfig() map[string]interface{} {
	return map[string]interface{}{
		"module":   "system",
		"datasets": []string{"process"},

		// To speed things up during testing, we effectively
		// disable hashing.
		"process.hash.max_file_size": 1,
	}
}

func testProcess() *Process {
	return &Process{
		Info: types.ProcessInfo{
			Name:      "zsh",
			PID:       9086,
			PPID:      9085,
			CWD:       "/home/elastic",
			Exe:       "/bin/zsh",
			Args:      []string{"zsh"},
			StartTime: time.Date(2019, 1, 1, 0, 0, 1, 0, time.UTC),
		},
		UserInfo: &types.UserInfo{
			UID:  "1000",
			EUID: "1000",
			SUID: "1000",
			GID:  "1000",
			EGID: "1000",
			SGID: "1000",
		},
		User: &user.User{
			Uid:      "1000",
			Username: "elastic",
		},
		Group: &user.Group{
			Gid:  "1000",
			Name: "elastic",
		},
		Hashes: map[hasher.HashType]hasher.Digest{
			hasher.SHA1: []byte("3de6a0a1cf514d15a61d3c873e2a710977c1103d"),
		},
	}
}
