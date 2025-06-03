package cmd

import (
	"bufio"
	"github.com/spf13/viper"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const DEFAULT_SKIP_USERS = "filterctl,relay"
const DEFAULT_MIN_UID = 1000
const DEFAULT_SCAN_SECONDS = 5
const DEFAULT_STABILIZE_SECONDS = 1
const DEFAULT_STABILIZE_COUNT = 5

var TRACE_PATTERN_MESSAGE = regexp.MustCompile(`^\s*Sieve trace log for message delivery:`)
var TRACE_PATTERN_DAEMON = regexp.MustCompile(`^\s*Sender:.*<[A-Z]+-DAEMON@.*>`)
var TRACE_PATTERN_EXECUTE = regexp.MustCompile(`^\s*## Started executing`)

type TraceFile struct {
	Username string
	Filename string
	Size     int64
	Count    int
}

type Monitor struct {
	ScanSeconds      int
	StabilizeSeconds int
	StabilizeCount   int
	MinUID           int
	SkipUsers        []string
	Domain           string
	UserHomes        map[string]string
	TraceFiles       map[string]*TraceFile
	Verbose          bool
	stop             chan struct{}
}

func NewMonitor() *Monitor {
	log.Printf("version %s startup\n", Version)
	viper.SetDefault("scan_interval_seconds", DEFAULT_SCAN_SECONDS)
	viper.SetDefault("stabilize_interval_seconds", DEFAULT_STABILIZE_SECONDS)
	viper.SetDefault("stabilize_count", DEFAULT_STABILIZE_COUNT)
	viper.SetDefault("skip_users", DEFAULT_SKIP_USERS)
	viper.SetDefault("min_uid", DEFAULT_MIN_UID)
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}
	_, domain, found := strings.Cut(hostname, ".")
	if !found {
		log.Fatalf("failed parsing domain from '%s'", hostname)
	}
	viper.SetDefault("domain", domain)
	monitor := Monitor{
		ScanSeconds:      viper.GetInt("scan_interval_seconds"),
		StabilizeSeconds: viper.GetInt("stabilize_interval_seconds"),
		StabilizeCount:   viper.GetInt("stabilize_count"),
		TraceFiles:       make(map[string]*TraceFile),
		MinUID:           viper.GetInt("min_uid"),
		SkipUsers:        strings.Split(viper.GetString("skip_users"), ","),
		Domain:           viper.GetString("domain"),
		UserHomes:        make(map[string]string),
		Verbose:          viper.GetBool("verbose"),
		stop:             make(chan struct{}),
	}
	monitor.initUserHomes()
	if monitor.Verbose {
		log.Printf("Monitor: %s\n", FormatJSON(&monitor))
	}
	return &monitor
}

func (m *Monitor) initUserHomes() {
	usernames := strings.Split(viper.GetString("usernames"), ",")
	for _, username := range usernames {
		username := strings.TrimSpace(username)
		if username != "" {
			home := filepath.Join("/home", username)
			if IsDir(home) && !m.skipUsername(username) {
				m.UserHomes[username] = home
				if m.Verbose {
					log.Printf("added user from config: %s\n", username)
				}
			}
		}
	}

	if len(m.UserHomes) == 0 {
		m.initUserHomesFromPasswd()
	}
}

func (m *Monitor) skipUsername(username string) bool {
	if slices.Contains(m.SkipUsers, username) {
		return true
	}
	if strings.HasPrefix(username, "_") {
		return true
	}
	return false
}

func (m *Monitor) initUserHomesFromPasswd() {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) > 0 {
			username := fields[0]
			uid, err := strconv.Atoi(fields[2])
			if err != nil {
				log.Fatalf("failed uid int conversion: %v", err)
			}
			home := fields[5]
			if uid >= m.MinUID && IsDir(home) && !m.skipUsername(username) {
				m.UserHomes[username] = home
				if m.Verbose {
					log.Printf("added user from /etc/passwd: %s\n", username)
				}
			}
		}
	}
	err = scanner.Err()
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Monitor) scanFiles() {
	deleteKeys := []string{}
	for key, file := range m.TraceFiles {
		if file.scan(m) {
			deleteKeys = append(deleteKeys, key)
		}
	}
	for _, key := range deleteKeys {
		if m.Verbose {
			log.Printf("deleting: %+v\n", m.TraceFiles[key])
		}
		delete(m.TraceFiles, key)
	}
}

func (t *TraceFile) scan(m *Monitor) bool {
	stat, err := os.Stat(t.Filename)
	if err != nil {
		log.Fatal(err)
	}
	if t.Size == stat.Size() {
		// if the file size has not changed, bump the counter
		t.Count += 1
		if m.Verbose {
			log.Printf("bump: %+v\n", *t)
		}
	} else {
		// the file size has changed, remember the new size and reset the counter
		t.Size = stat.Size()
		t.Count = 0
		if m.Verbose {
			log.Printf("changed: %+v\n", *t)
		}
	}
	if t.Count >= m.StabilizeCount {
		if m.Verbose {
			log.Printf("stabilized: %+v\n", *t)
		}
		if t.shouldForward(m) {
			err := SendFile(t.Username, m.Domain, t.Filename)
			if err != nil {
				log.Fatal(err)
			}
		}
		if m.Verbose {
			log.Printf("removing: %s\n", t.Filename)
		}
		err = os.Remove(t.Filename)
		if err != nil {
			log.Fatal(err)
		}
		return true
	}
	return false
}

func (t *TraceFile) shouldForward(m *Monitor) bool {

	file, err := os.Open(t.Filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	defer func() {
		err = scanner.Err()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// default to skip
	forward := false
	reason := "non_message_delivery_trace"

	for scanner.Scan() {
		line := scanner.Text()
		if TRACE_PATTERN_MESSAGE.MatchString(line) {
			reason = "message_delivery_trace"
			forward = true
		}
		if TRACE_PATTERN_DAEMON.MatchString(line) {
			reason = "sender_is_daemon"
			forward = false
		}
		if TRACE_PATTERN_EXECUTE.MatchString(line) {
			break
		}
	}
		action := "Forwarding"
		if !forward {
			action = "Skipping"
		}
		log.Printf("%s %s: %s\n", action, reason, t.Filename)
	return forward
}

func (m *Monitor) scanDirs() {
	for user, home := range m.UserHomes {
		dir := filepath.Join(home, "sieve_trace")
		if IsDir(dir) {
			if m.Verbose {
				log.Printf("scanning: %s\n", dir)
			}
			pattern := filepath.Join(dir, "*.trace")
			files, err := filepath.Glob(pattern)
			if err != nil {
				log.Fatalf("failed scanning %s: %v", pattern, err)
			}
			for _, filename := range files {
				_, found := m.TraceFiles[filename]
				if !found {
					stat, err := os.Stat(filename)
					if err != nil {
						log.Fatal(err)
					}
					// record the new file for stabilization check
					file := TraceFile{
						Username: user,
						Filename: filename,
						Size:     stat.Size(),
						Count:    0,
					}
					m.TraceFiles[filename] = &file
					if m.Verbose {
						log.Printf("added: %+v\n", file)
					}
				}

			}
		}
	}
}

func (m *Monitor) Run() error {
	log.Printf("monitoring sieve_trace directories")
	scanSeconds := viper.GetInt64("scan_interval_seconds")
	scanTicker := time.NewTicker(time.Duration(scanSeconds) * time.Second)
	stabilizeSeconds := viper.GetInt64("stabilize_interval_seconds")
	stabilizeTicker := time.NewTicker(time.Duration(stabilizeSeconds) * time.Second)
	for {
		select {
		case <-scanTicker.C:
			m.scanDirs()
		case <-stabilizeTicker.C:
			m.scanFiles()
		case <-m.stop:
			log.Printf("exiting")
			return nil
		}
	}
}
