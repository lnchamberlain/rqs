package main

/* ------ RQS ------
 * userland component - enumerates /proc/[pid]/task and reports the discoverable
 * pids to the scanner LKM by writing to /proc/rqs_report
 * Format for writes: [GENERATION][PID MAX IN BATCH][PID COUNT][PID][PID]....
 */

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const REPORT_ENDPOINT string = "/proc/rqs_report"

const LOG_PATH string = "/var/log/rqs-userland.log"

var logger *log.Logger

var scanEpoch *uint

var scanGeneration uint

func scanAndReport() error {
	/* open handle to reporting endpoint */
	reportEndpoint, err := os.OpenFile(REPORT_ENDPOINT, os.O_WRONLY, 0)
	if err != nil {
		return nil //err - disable this error for now so the userland part can be loaded as a service before the scanner lkm has created the procfs entry
	}
	defer reportEndpoint.Close()

	var seenPids []int
	pidMax := 0

	/* read /proc */
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, proc := range procs {
		/* ony process entries that can be parsed into integers (pid dirs) */
		tgid, err := strconv.Atoi(proc.Name())
		if err == nil && tgid > 0 {
			/* read /proc/[pid]/task to view thread ids */
			threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", tgid))
			if err != nil {
				continue
			}
			for _, thread := range threads {
				pid, err := strconv.Atoi(thread.Name())
				if err == nil && pid > 0 {
					if pid > pidMax {
						/* keep track of the max - kernel allocates a bitmap of this size */
						pidMax = pid
					}
					seenPids = append(seenPids, pid)
				}
			}
		}
	}
	/* assemble the snapshot string */
	var sb strings.Builder
	fmt.Fprintf(&sb, "GEN %d MAX %d COUNT %d ", scanGeneration, pidMax, len(seenPids))
	for _, p := range seenPids {
		fmt.Fprintf(&sb, "%d ", p)
	}
	sb.WriteByte('\n')

	/* pass the message to the kernel */
	_, err = reportEndpoint.Write([]byte(sb.String()))
	logger.Printf("rqs-userland: sent - GEN %d MAX %d COUNT %d\n", scanGeneration, pidMax, len(seenPids))
	scanGeneration++
	if err != nil {
		return err
	}

	return nil
}

func main() {

	/* open log file */
	file, err := os.OpenFile(LOG_PATH, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0640)
	if err != nil {
		log.Fatal(err)
	}

	logger = log.New(file, "", log.LstdFlags)
	logger.Println("rqs-userland: startup...")

	/* seed the gen with a higher number so the kernel doesn't reject the snapshots*/
	scanGeneration = uint(time.Now().Unix())

	/* command line arg parsing*/
	scanEpoch = flag.Uint("scanEpoch", 5, "Duration in seconds between scans")
	flag.Parse()

	if *scanEpoch > 1000 || *scanEpoch < 1 {
		fmt.Printf("rqs-userland: invalid scanEpoch %d. defaulting to 5.\n", *scanEpoch)
		*scanEpoch = 5
	}
	logger.Printf("rqs-userland: using scanEpoch: %d\n", *scanEpoch)

	/* scan and report until interrupted  */
	for {
		err := scanAndReport()
		if err != nil {
			logger.Printf("rqs-userland: error performing scan: %s\n", err)
		}
		time.Sleep(time.Duration(*scanEpoch) * time.Second)
	}
}
