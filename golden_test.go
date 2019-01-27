package ice

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var writeGolden = flag.Bool("golden", false, "write golden files")

func packageDir(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to get package directory")
	}
	return filepath.Dir(filename)
}

func goldenName(t *testing.T, name string) string {
	return filepath.Join(packageDir(t), "_testdata", name)
}

func readGolden(t *testing.T, name string) (*os.File, func()) {
	f, err := os.Open(goldenName(t, name))
	if err != nil {
		t.Fatal("failed to read", err)
	}
	return f, func() {
		if err = f.Close(); err != nil {
			t.Error(err)
		}
	}
}

func createGolden(t *testing.T, name string) (*os.File, func()) {
	t.Helper()
	f, err := os.Create(filepath.Join("_testdata", name))
	if err != nil {
		t.Fatal("failed to create", err)
	}
	t.Logf("golden file created: %s", f.Name())
	return f, func() {
		if err = f.Close(); err != nil {
			t.Error(err)
		}
	}
}

func saveGoldenJSON(t *testing.T, v interface{}, name string) {
	t.Helper()
	fUpd, closeFUpd := createGolden(t, name)
	defer closeFUpd()
	e := json.NewEncoder(fUpd)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
}

func loadGoldenJSON(t *testing.T, v interface{}, name string) {
	f, closeF := readGolden(t, name)
	defer closeF()
	d := json.NewDecoder(f)
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}
