package login

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
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
	} else if len(events) != 1 {
		t.Fatalf("only one event expected, got %d", len(events))
	}

	events[0].RootFields.Put("event.origin", "/var/log/wtmp")
	fullEvent := mbtest.StandardizeEvent(f, events[0], core.AddDatasetToEvent)
	mbtest.WriteEventToDataJSON(t, fullEvent, "")
}

func TEstWtmp(t *testing.T) {
	if byteOrder != binary.LittleEndian {
		t.Skip("Test only works on little-endian system - skipping.")
	}

	defer SetupDataDir(t)()

}

func getBaseConfig() map[string]interface{} {
	return map[string]interface{}{
		"module":   "system",
		"datasets": []string{"login"},
	}
}

// setupTestDir creates a temporary directory, copies the test files into it,
// and returns the path.
func setupTestDir(t *testing.T) string {
	tmp, err := os.MkdirTemp("", "auditbeat-login-test-dir")
	if err != nil {
		t.Fatal("failed to create temp dir")
	}

	copyDir(t, "./testdata", tmp)

	return tmp
}

func copyDir(t *testing.T, src, dst string) {
	files, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("failed to read %v", src)
	}

	for _, file := range files {
		srcFile := filepath.Join(src, file.Name())
		dstFile := filepath.Join(dst, file.Name())
		copyFile(t, srcFile, dstFile)
	}
}

func copyFile(t *testing.T, src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("failed to open %v", src)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("failed to open %v", dst)
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		t.Fatalf("failed to copy %v to %v", src, dst)
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
