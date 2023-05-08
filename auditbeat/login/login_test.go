package login

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/elastic/beats/v7/auditbeat/core"
	"github.com/elastic/beats/v7/libbeat/paths"
	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
)

func TestWtmp(t *testing.T) {
	if byteOrder != binary.LittleEndian {
		t.Skip("Test only work on little-endian system -skipping.")
	}

	defer SetupDataDir(t)()

	config := getBaseConfig()
	config["login.wtmp_file_pattern"] = "./testdata/wtmp"
	config["login.btmp_file_pattern"] = ""
	f := mbtest.NewReportingMetricSetV2(t, config)
	defer f.(*MetricSet).utmpReader.bucket.DeleteBucket()

	events, errs := mbtest.ReportingFetchV2(f)
	if len(errs) > 0 {
		t.Fatalf("received error: %+v", errs[0])
	}

	if len(events) == 0 {
		t.Fatal("no evnets were generated")
	}else if len(events) != 1 {
		t.Fatalf("only one event expected, got %d", len(events))
	}

	events[0].RootFields.Put("event.origin", "/var/log/wtmp")
	fullEvent := mbtest.StandardizeEvent(f, events[0], core.AddDatasetToEvent)
	mbtest.WriteEventToDataJSON(t, fullEvent, "")
}

func getBaseConfig() map[string]interface{} {
	return map[string]interface{}{
		"module":   "system",
		"datasets": []string{"login"},
	}
}

func SetupDataDir(t testing.TB) func() {
	var err error
	paths.Paths.Data, err = os.MkdirTemp("", "beat-data-dir")
	if err != nil {
		t.Fatal()
	}
	return func() { os.RemoveAll(paths.Paths.Data) }
}
