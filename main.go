package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
)

// defaultDataDir: --data flag > LOGSIKKA_DATA (or FORTILOG_DATA) > %PROGRAMDATA%\LogSikka (Windows) > /var/lib/logsikka (Linux).
// v6.0: an installation that still has only the LogSikka folder keeps using it.
// config.json, spool/ and spool/quarantine/ all live here, so the service user only needs write access to one folder.
func defaultDataDir() string {
	for _, k := range []string{"LOGSIKKA_DATA", "FORTILOG_DATA"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("PROGRAMDATA"); v != "" {
			return firstExisting(filepath.Join(v, "LogSikka"), filepath.Join(v, "FortiLogCollector"))
		}
	}
	if runtime.GOOS == "linux" {
		return firstExisting("/var/lib/logsikka", "/var/lib/fortilog")
	}
	return dataDir()
}

func main() {
	data := flag.String("data", defaultDataDir(), "data directory (config.json and spool)")
	configPath := flag.String("config", "", "configuration file (default <data>/config.json)")
	flag.Parse()
	if *configPath == "" {
		*configPath = filepath.Join(*data, "config.json")
	}
	// account management from the shell: logsikka --data DIR user ...
	if flag.Arg(0) == "user" {
		if err := runUserCLI(filepath.Dir(*configPath), flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*configPath), 0750); err != nil {
		log.Fatal(err)
	}
	store, e := LoadConfig(*configPath)
	if e != nil {
		log.Fatal(e)
	}
	log.Printf("LogSikka %s starting: config %s, spool %s, time zone %s", version, *configPath, store.Get().SpoolDirectory, timeZoneName())
	app := NewApp(store)
	if service, _ := isService(); service {
		if e = runService(app); e != nil {
			log.Fatal(e)
		}
		return
	}
	// Linux / systemd and console runs: SIGTERM (systemctl stop) and Ctrl+C both shut down cleanly and flush the batch.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = app.Run(ctx); e != nil {
		log.Fatal(e)
	}
}

// version of this build (shown in the log, the header and System health).
const version = "v6.0.16"

// firstExisting: the new folder when it exists or when neither exists, otherwise the old one (LogSikka upgrades).
func firstExisting(newDir, oldDir string) string {
	if _, err := os.Stat(newDir); err == nil {
		return newDir
	}
	if _, err := os.Stat(oldDir); err == nil {
		return oldDir
	}
	return newDir
}
