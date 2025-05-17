package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf ../bpf/nomad_watcher.bpf.c -- -I../bpf -nostdinc -I/usr/include

// --- Structs ---
const maxIdentifierLen = 512

type sniEventT struct{ Identifier [maxIdentifierLen]byte }

type NomadJobStatus struct {
	Status string `json:"Status"`
	ID     string `json:"ID"`
}
type NomadJobRegisterResponse struct {
	EvalID          string `json:"EvalID"`
	EvalCreateIndex int64  `json:"EvalCreateIndex"`
	JobModifyIndex  int64  `json:"JobModifyIndex"`
	Warnings        string `json:"Warnings"`
	Index           int64  `json:"Index"`
	LastContact     int64  `json:"LastContact"`
	KnownLeader     bool   `json:"KnownLeader"`
}

type NomadTaskEvent struct {
	Type           string            `json:"Type"`
	Time           int64             `json:"Time"` // Unix nanoseconds
	Message        string            `json:"Message,omitempty"`
	DisplayMessage string            `json:"DisplayMessage,omitempty"`
	Details        map[string]string `json:"Details,omitempty"`
	FailsTask      bool              `json:"FailsTask,omitempty"`
	ExitCode       *int              `json:"ExitCode,omitempty"`
	Signal         *int              `json:"Signal,omitempty"`
	DriverError    string            `json:"DriverError,omitempty"`
}

type NomadTaskState struct {
	State       string           `json:"State"`
	Failed      bool             `json:"Failed"`
	Restarts    int              `json:"Restarts"`
	LastRestart *time.Time       `json:"LastRestart,omitempty"`
	StartedAt   *time.Time       `json:"StartedAt,omitempty"`
	FinishedAt  *time.Time       `json:"FinishedAt,omitempty"`
	Events      []NomadTaskEvent `json:"Events"`
}

type NomadAllocationListStub struct {
	ID               string                    `json:"ID"`
	Name             string                    `json:"Name"`
	JobID            string                    `json:"JobID"`
	ClientStatus     string                    `json:"ClientStatus"`
	DesiredStatus    string                    `json:"DesiredStatus"`
	TaskStates       map[string]NomadTaskState `json:"TaskStates"`
	CreateIndex      int64                     `json:"CreateIndex"`
	ModifyIndex      int64                     `json:"ModifyIndex"`
	DeploymentStatus *DeploymentStatus         `json:"DeploymentStatus,omitempty"`
}

type DeploymentStatus struct {
	Healthy   bool      `json:"Healthy"`
	Timestamp time.Time `json:"Timestamp"`
	Canary    bool      `json:"Canary"`
}

// --- Global Variables ---
var (
	httpClient = &http.Client{Timeout: 10 * time.Second}
	nomadAddr  string
	nomadToken string

	jobStatusMap *ebpf.Map
	statusMapKey = uint32(0)
	statusLock   = &sync.Mutex{}

	pollingJobs     = make(map[string]context.CancelFunc)
	pollingJobsLock = &sync.Mutex{}
)

const defaultTaskGroupCount = 1
const pollHealthyTimeout = 1 * time.Minute

// Short poll interval for responsiveness after delay expires
const pollHealthyInterval = 3 * time.Second

const mainTaskName = "main"
const targetHookName = "poststart"

// The required delay AFTER the poststart hook completes successfully
const postHookCompletionDelay = 3 * time.Second

// --- NEW: Additional grace period AFTER readiness is detected ---
const additionalRejectionGracePeriod = 6 * time.Second

// --- SNI Parsing Logic --- (Truncated for brevity)
const (
	tlsRecordHeaderLen = 5
	tlsHandshake       = 22
	tlsClientHello     = 1
	tlsExtensionSNI    = 0
	tlsSNIHostname     = 0
)

func extractSNIFromPayload(payload []byte) (string, error) {
	payloadLen := len(payload)
	if payloadLen < tlsRecordHeaderLen || payload[0] != tlsHandshake {
		return "", errors.New("not a TLS handshake record or too short")
	}
	if payloadLen < 5 {
		return "", errors.New("payload too short for record length read")
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	recordBoundary := tlsRecordHeaderLen + recordLen
	if payloadLen < recordBoundary {
		return "", fmt.Errorf("payload buffer (%d bytes) shorter than TLS record length (%d bytes)", payloadLen, recordLen)
	}
	hsHeaderOffset := tlsRecordHeaderLen
	if hsHeaderOffset+4 > recordBoundary {
		return "", errors.New("payload too short for handshake header")
	}
	handshakeType := payload[hsHeaderOffset]
	if handshakeType != tlsClientHello {
		return "", errors.New("not a ClientHello handshake message")
	}
	chBodyOffset := hsHeaderOffset + 4
	if chBodyOffset+2 > recordBoundary {
		return "", errors.New("payload too short for CH version")
	}
	chBodyOffset += 2
	if chBodyOffset+32 > recordBoundary {
		return "", errors.New("payload too short for CH random")
	}
	chBodyOffset += 32
	if chBodyOffset+1 > recordBoundary {
		return "", errors.New("payload too short for Session ID len")
	}
	sessionIdLen := int(payload[chBodyOffset])
	chBodyOffset += 1
	if chBodyOffset+sessionIdLen > recordBoundary {
		return "", errors.New("payload too short for Session ID")
	}
	chBodyOffset += sessionIdLen
	if chBodyOffset+2 > recordBoundary {
		return "", errors.New("payload too short for Cipher Suite len")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[chBodyOffset : chBodyOffset+2]))
	chBodyOffset += 2
	if chBodyOffset+cipherSuitesLen > recordBoundary {
		return "", errors.New("payload too short for Cipher Suites")
	}
	chBodyOffset += cipherSuitesLen
	if chBodyOffset+1 > recordBoundary {
		return "", errors.New("payload too short for Comp Methods len")
	}
	compressionMethodsLen := int(payload[chBodyOffset])
	chBodyOffset += 1
	if chBodyOffset+compressionMethodsLen > recordBoundary {
		return "", errors.New("payload too short for Comp Methods")
	}
	chBodyOffset += compressionMethodsLen
	if chBodyOffset == recordBoundary {
		return "", errors.New("no extensions found")
	}
	if chBodyOffset+2 > recordBoundary {
		return "", errors.New("payload too short for Extensions len")
	}
	extensionsTotalLen := int(binary.BigEndian.Uint16(payload[chBodyOffset : chBodyOffset+2]))
	chBodyOffset += 2
	extensionsEnd := chBodyOffset + extensionsTotalLen
	if extensionsEnd > recordBoundary {
		return "", errors.New("extensions length exceeds record boundary")
	}
	currentExtOffset := chBodyOffset
	for currentExtOffset+4 <= extensionsEnd {
		extensionType := binary.BigEndian.Uint16(payload[currentExtOffset : currentExtOffset+2])
		extensionLen := int(binary.BigEndian.Uint16(payload[currentExtOffset+2 : currentExtOffset+4]))
		currentExtOffset += 4
		if currentExtOffset+extensionLen > extensionsEnd {
			return "", errors.New("extension data length exceeds extensions boundary")
		}
		if extensionType == tlsExtensionSNI {
			sniDataOffset := currentExtOffset
			if extensionLen < 2 {
				return "", errors.New("SNI extension data too short for list length")
			}
			sniListLen := int(binary.BigEndian.Uint16(payload[sniDataOffset : sniDataOffset+2]))
			if 2+sniListLen > extensionLen {
				return "", errors.New("SNI list length exceeds extension length")
			}
			currentNameOffset := sniDataOffset + 2
			if currentNameOffset+3 <= sniDataOffset+2+sniListLen {
				nameType := payload[currentNameOffset]
				nameLen := int(binary.BigEndian.Uint16(payload[currentNameOffset+1 : currentNameOffset+3]))
				currentNameOffset += 3
				if currentNameOffset+nameLen > sniDataOffset+2+sniListLen {
					return "", errors.New("SNI name length exceeds SNI list boundary")
				}
				if nameType == tlsSNIHostname {
					serverName := string(payload[currentNameOffset : currentNameOffset+nameLen])
					return serverName, nil
				}
				break
			}
			return "", errors.New("SNI extension found, but no valid hostname entry processed")
		}
		currentExtOffset += extensionLen
	}
	return "", errors.New("SNI extension not found after looping")
}

// hasPoststartCompletedPlusDelay checks if the poststart hook completed successfully AND the delay has passed.
// NOTE: This function *only* checks the original delay, not the additional grace period.
func hasPoststartCompletedPlusDelay(ctx context.Context, jobID string) (bool, error) {
	allocsURL := fmt.Sprintf("%s/v1/job/%s/allocations?task_states=true", nomadAddr, jobID)
	req, err := http.NewRequestWithContext(ctx, "GET", allocsURL, nil)
	if err != nil {
		return false, fmt.Errorf("creating allocations request for job %s: %w", jobID, err)
	}
	if nomadToken != "" {
		req.Header.Set("X-Nomad-Token", nomadToken)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("executing allocations request for job %s: %w", jobID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return false, fmt.Errorf("nomad API returned status %d for allocations of job %s: %s", resp.StatusCode, jobID, string(bodyBytes))
	}

	var allocations []NomadAllocationListStub
	if err := json.NewDecoder(resp.Body).Decode(&allocations); err != nil {
		return false, fmt.Errorf("decoding allocations response for job %s: %w", jobID, err)
	}

	if len(allocations) == 0 {
		log.Printf("  HEALTH CHECK [%s]: No allocations found.", jobID)
		return false, nil
	}

	var latestSuccessfulPoststartHookCompletionTime time.Time
	foundHookCompletion := false

	for _, alloc := range allocations {
		if strings.ToLower(alloc.ClientStatus) != "running" {
			continue
		}

		mainTaskState, ok := alloc.TaskStates[mainTaskName]
		if !ok {
			continue
		}

		for _, event := range mainTaskState.Events {
			hookNameInDetails, detailsOk := event.Details["hook_name"]
			if !detailsOk {
				hookNameInDetails, detailsOk = event.Details["hook"] // Older Nomad versions
			}

			if detailsOk && hookNameInDetails == targetHookName &&
				event.Type == "Terminated" && event.ExitCode != nil && *event.ExitCode == 0 {

				eventTime := time.Unix(0, event.Time)
				if eventTime.After(latestSuccessfulPoststartHookCompletionTime) {
					latestSuccessfulPoststartHookCompletionTime = eventTime
					foundHookCompletion = true
				}
			}
		}
	}

	if !foundHookCompletion {
		// Reduced verbosity: Log only when polling or first check, not every single health check.
		// log.Printf("  HEALTH CHECK [%s]: No successful '%s' hook termination found yet for task '%s' in any running allocation.", jobID, targetHookName, mainTaskName)
		return false, nil
	}

	targetReadyTime := latestSuccessfulPoststartHookCompletionTime.Add(postHookCompletionDelay)
	if time.Now().After(targetReadyTime) {
		// Don't log success here every time, the poller will log when it acts.
		// log.Printf("  HEALTH CHECK [%s]: SUCCESS! Hook '%s' completed at %s and post-hook delay (%s) passed (ready at %s).",
		//  jobID, targetHookName, latestSuccessfulPoststartHookCompletionTime.Format(time.RFC3339), postHookCompletionDelay, targetReadyTime.Format(time.RFC3339))
		return true, nil // Condition met (original delay passed)
	}

	// Reduced verbosity
	// log.Printf("  HEALTH CHECK [%s]: Hook '%s' completed at %s, but post-hook delay (%s) not yet passed (current: %s, target ready: %s).",
	//  jobID, targetHookName, latestSuccessfulPoststartHookCompletionTime.Format(time.RFC3339), postHookCompletionDelay, time.Now().Format(time.RFC3339), targetReadyTime.Format(time.RFC3339))
	return false, nil // Original delay not yet passed
}

// handleRingbufRecord processes events from BPF.
// It sets the state to REJECT and starts the poller if not ready.
// If ready, it logs but lets the poller handle the final ALLOW transition after the grace period.
func handleRingbufRecord(ctx context.Context, record ringbuf.Record) {
	var event sniEventT
	payloadLen := 0
	for i, b := range record.RawSample {
		if i >= maxIdentifierLen {
			payloadLen = maxIdentifierLen
			break
		}
		event.Identifier[i] = b
		payloadLen = i + 1
	}

	serverName, err := extractSNIFromPayload(event.Identifier[:payloadLen])
	if err != nil {
		// Ignore non-SNI packets or parsing errors silently
		return
	}

	identifier := serverName
	if idx := strings.IndexByte(serverName, '.'); idx >= 0 {
		identifier = serverName[:idx] // Use part before first dot as identifier
	}
	if identifier == "" {
		log.Printf("WARN: Empty identifier derived from SNI '%s'", serverName)
		return
	}
	nomadJobID := identifier + "-compute" // Assuming job naming convention

	log.Printf("INFO: SNI detected for Job ID '%s' (SNI: '%s'). Checking primary readiness...", nomadJobID, serverName)

	// --- Get Job Spec (for potential restart) ---
	var jobSpecBytes []byte
	statusURL := fmt.Sprintf("%s/v1/job/%s", nomadAddr, nomadJobID)
	specReq, _ := http.NewRequest("GET", statusURL, nil) // Use background context for spec fetch
	if nomadToken != "" {
		specReq.Header.Set("X-Nomad-Token", nomadToken)
	}
	specResp, specErr := httpClient.Do(specReq)
	if specErr == nil {
		if specResp.StatusCode == http.StatusOK {
			jobSpecBytes, _ = ioutil.ReadAll(specResp.Body)
		} else {
			log.Printf("  WARN: Failed to get job spec for %s (status %d), cannot auto-restart if needed.", nomadJobID, specResp.StatusCode)
		}
		specResp.Body.Close() // Always close body
	} else {
		log.Printf("  WARN: Error getting job spec for %s: %v. Cannot auto-restart.", nomadJobID, specErr)
	}
	// --- End Get Job Spec ---

	// Perform the primary readiness check (hook completed + original delay passed?)
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second) // Short timeout for this check
	isPrimaryReady, healthCheckErr := hasPoststartCompletedPlusDelay(checkCtx, nomadJobID)
	checkCancel()

	if healthCheckErr != nil {
		log.Printf("  ERROR: Primary readiness check for job %s failed: %v. Assuming not ready, ensuring REJECT(0).", nomadJobID, healthCheckErr)
		updateJobStatusMap(0)                                // Ensure REJECT on error
		ensurePollerIsRunning(ctx, nomadJobID, jobSpecBytes) // Start poller to recover
		return
	}

	if isPrimaryReady {
		// Condition met: hook completed and original delay passed
		// BUT we don't allow yet. The poller handles the final grace period and ALLOW.
		log.Printf("  INFO: Job %s meets primary readiness criteria (hook '%s' + %s delay). Poller will handle final %s grace period before allowing.",
			nomadJobID, targetHookName, postHookCompletionDelay, additionalRejectionGracePeriod)

		// If the map is *already* allow, it means a poller finished its job. We can cancel any *stale* poller reference
		// but mostly we just ensure one *is* running if the state is currently REJECT.
		statusLock.Lock()
		var currentVal uint8
		err := jobStatusMap.Lookup(statusMapKey, &currentVal)
		statusLock.Unlock() // Unlock immediately after lookup

		if err == nil && currentVal == 1 {
			// Already allowing. Maybe cancel any stray poller?
			pollingJobsLock.Lock()
			if cancel, ok := pollingJobs[nomadJobID]; ok {
				log.Printf("  INFO: Job %s already allowing. Cancelling potentially stale poller.", nomadJobID)
				cancel()
				delete(pollingJobs, nomadJobID)
			}
			pollingJobsLock.Unlock()
		} else {
			// Not allowing yet (or map error), ensure poller is running to manage the transition.
			log.Printf("  INFO: Job %s is primary ready but BPF state is REJECT(0) or unknown. Ensuring poller runs to manage grace period.", nomadJobID)
			ensurePollerIsRunning(ctx, nomadJobID, jobSpecBytes)
		}
		return // Let poller handle the final ALLOW

	} else {
		// Condition not met: hook not complete OR original delay not passed
		log.Printf("  INFO: Job %s does NOT meet primary readiness criteria. Ensuring BPF is REJECT(0) and poller is running.", nomadJobID)
		updateJobStatusMap(0)                                // Set to REJECT
		ensurePollerIsRunning(ctx, nomadJobID, jobSpecBytes) // Ensure poller runs to eventually allow
		return
	}
}

// ensurePollerIsRunning starts a poller if one isn't already running for the jobID.
func ensurePollerIsRunning(ctx context.Context, nomadJobID string, jobSpecBytes []byte) {
	pollingJobsLock.Lock()
	_, pollerExists := pollingJobs[nomadJobID]

	// If no poller exists, consider starting/restarting the job in the background.
	// Do this *before* starting the poller goroutine.
	if !pollerExists {
		if jobSpecBytes != nil {
			log.Printf("  POLLER_MGR: No active poller for %s. Attempting background job start/update.", nomadJobID)
			// Run non-blockingly
			go startNomadJob(nomadJobID, jobSpecBytes)
		} else {
			log.Printf("  POLLER_MGR: No active poller for %s. Cannot start/update job (spec missing).", nomadJobID)
		}
	}

	if pollerExists {
		// log.Printf("  POLLER_MGR: Poller already running for %s.", nomadJobID) // Reduce verbosity
		pollingJobsLock.Unlock()
		return // Poller already running
	}

	log.Printf("  POLLER_MGR: Starting new poller for %s.", nomadJobID)
	pollerCtx, pollerCancel := context.WithCancel(ctx) // Create a new context for this poller
	pollingJobs[nomadJobID] = pollerCancel
	pollingJobsLock.Unlock() // Unlock before starting goroutine

	go pollUntilHealthy(pollerCtx, nomadJobID, pollerCancel)
}

// pollUntilHealthy polls until the health condition (poststart hook + original delay) is met,
// then waits for the additionalRejectionGracePeriod before setting BPF to ALLOW.
func pollUntilHealthy(ctx context.Context, jobID string, cancelSelf context.CancelFunc) {
	log.Printf("  POLLER [%s]: Started. Poll interval: %s. Will poll for primary readiness (hook '%s' + %s delay), then wait %s before allowing. Timeout: %v.",
		jobID, pollHealthyInterval, targetHookName, postHookCompletionDelay, additionalRejectionGracePeriod, pollHealthyTimeout)

	// Cleanup function to remove self from the polling map
	defer func() {
		pollingJobsLock.Lock()
		// Only delete if the cancel func in the map is the one for *this* instance
		if c, ok := pollingJobs[jobID]; ok && &c == &cancelSelf {
			delete(pollingJobs, jobID)
		} else if ok {
			log.Printf("  POLLER [%s]: Exiting, but found a different/newer poller registered. Not removing from map.", jobID)
		}
		pollingJobsLock.Unlock()
		log.Printf("  POLLER [%s]: Exiting.", jobID)
	}()

	ticker := time.NewTicker(pollHealthyInterval)
	defer ticker.Stop()
	timeoutTimer := time.NewTimer(pollHealthyTimeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			// Use a shorter timeout for the check itself than the poll interval
			checkTimeout := pollHealthyInterval - (50 * time.Millisecond)
			if checkTimeout <= 0 {
				checkTimeout = pollHealthyInterval / 2
			}
			if checkTimeout <= 0 {
				checkTimeout = 100 * time.Millisecond // Minimum check timeout
			}

			checkCtx, checkCancel := context.WithTimeout(ctx, checkTimeout)
			// Check if hook completed + *original* delay passed
			isPrimaryReady, err := hasPoststartCompletedPlusDelay(checkCtx, jobID)
			checkCancel() // Release context resources promptly

			if err != nil {
				log.Printf("  POLLER [%s]: ERROR checking primary readiness: %v. Ensuring REJECT(0).", jobID, err)
				updateJobStatusMap(0) // Ensure REJECT on error
				continue              // Continue polling
			}

			if isPrimaryReady {
				log.Printf("  POLLER [%s]: Job meets primary readiness criteria. Waiting additional %s before allowing traffic...", jobID, additionalRejectionGracePeriod)

				// Wait for the additional grace period, but allow cancellation
				graceTimer := time.NewTimer(additionalRejectionGracePeriod)
				select {
				case <-graceTimer.C:
					// Grace period finished. Proceed to allow.
					log.Printf("  POLLER [%s]: Additional grace period (%s) finished. Setting BPF to ALLOW(1).", jobID, additionalRejectionGracePeriod)
					updateJobStatusMap(1)
					// Stop the timer explicitly though defer would handle it too
					if !graceTimer.Stop() {
						<-graceTimer.C // Drain channel if Stop returns false
					}
					return // Success, exit poller

				case <-ctx.Done():
					// Poller context was cancelled during the grace period wait
					log.Printf("  POLLER [%s]: Context cancelled during grace period wait. Shutting down poller. BPF state unchanged by this poller.", jobID)
					if !graceTimer.Stop() {
						// If timer already fired and we somehow got here, drain channel
						select {
						case <-graceTimer.C:
						default:
						}
					}
					return // Exit poller due to cancellation
				}
				// Should not reach here
			} else {
				// Not yet ready based on primary check. Ensure BPF is rejecting.
				// log.Printf("  POLLER [%s]: Job not yet primary ready. Ensuring BPF is REJECT(0).", jobID) // Reduce verbosity
				updateJobStatusMap(0) // Ensure REJECT while polling and not ready
			}

		case <-timeoutTimer.C:
			log.Printf("  POLLER [%s]: TIMEOUT (%v) reached polling for readiness. Setting BPF to ALLOW(1) to unblock (bypassing grace period).", jobID, pollHealthyTimeout)
			updateJobStatusMap(1) // Unblock port on timeout
			return                // Exit poller due to timeout

		case <-ctx.Done():
			log.Printf("  POLLER [%s]: Context cancelled. Shutting down poller.", jobID)
			return // Exit poller due to cancellation
		}
	}
}

// startNomadJob (User's version with 3s sleep - unchanged from provided)
func startNomadJob(jobID string, jobSpecBytes []byte) {
	log.Printf("    Attempting background start/update for job %s...", jobID)
	if jobSpecBytes == nil {
		log.Printf("    ERROR: Cannot start/update job %s, job specification is missing.", jobID)
		return
	}
	var jobData map[string]interface{}
	if err := json.Unmarshal(jobSpecBytes, &jobData); err != nil {
		log.Printf("    ERROR: Unmarshalling job spec for %s: %v. Job spec might not be a direct map[string]interface{}.", jobID, err)
		// It might be nested under "Job", try that
		var nestedJobData struct {
			Job map[string]interface{} `json:"Job"`
		}
		if errNested := json.Unmarshal(jobSpecBytes, &nestedJobData); errNested == nil && nestedJobData.Job != nil {
			log.Printf("    INFO: Unmarshalled job spec nested under 'Job' key for %s.", jobID)
			jobData = nestedJobData.Job
		} else {
			log.Printf("    ERROR: Still failed to unmarshal job spec for %s after checking nesting: %v (nested error: %v)", jobID, err, errNested)
			return
		}
	}

	// Ensure the job isn't stopped and has the correct count
	jobData["Stop"] = false // Ensure job is set to run
	modifiedCount := false
	if taskGroups, ok := jobData["TaskGroups"].([]interface{}); ok && len(taskGroups) > 0 {
		if firstGroup, ok := taskGroups[0].(map[string]interface{}); ok {
			currentCountVal, hasCount := firstGroup["Count"]
			desiredCount := float64(defaultTaskGroupCount) // Ensure desired count is float64 for comparison/setting
			needsUpdate := !hasCount
			if hasCount {
				if currentCountFloat, ok := currentCountVal.(float64); ok {
					if currentCountFloat != desiredCount {
						needsUpdate = true
					}
				} else {
					log.Printf("    WARN: TaskGroup count for job %s is not a float64: %T. Forcing update.", jobID, currentCountVal)
					needsUpdate = true // Force update if type is wrong
				}
			}
			if needsUpdate {
				firstGroup["Count"] = desiredCount // Set as float64
				modifiedCount = true
				log.Printf("    INFO: Set/Updated TaskGroup count to %d for job %s.", defaultTaskGroupCount, jobID)
			}
		} else {
			log.Printf("    WARN: Could not access first TaskGroup as map[string]interface{} for job %s.", jobID)
		}
	} else {
		log.Printf("    WARN: TaskGroups field missing or empty for job %s. Cannot verify/set count.", jobID)
	}

	if !modifiedCount {
		log.Printf("    INFO: TaskGroup count for %s is already %d or structure not matched for update. Proceeding with re-POST.", jobID, defaultTaskGroupCount)
	}

	// Re-wrap the potentially modified jobData in the {"Job": ...} structure for the API request
	payload := map[string]interface{}{"Job": jobData}
	postBodyBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("    ERROR: Marshalling payload for job %s: %v", jobID, err)
		return
	}

	postURL := fmt.Sprintf("%s/v1/jobs", nomadAddr) // Use /v1/jobs for registering/updating
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postBodyBytes))
	if err != nil {
		log.Printf("    ERROR: Creating re-register/update request for job %s: %v", jobID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if nomadToken != "" {
		req.Header.Set("X-Nomad-Token", nomadToken)
	}

	// Add idempotency token to prevent duplicate evaluations if the request is retried
	// req.URL.Query().Add("idempotency_token", generateSomeUUID()) // Example

	resp, errHttp := httpClient.Do(req)
	if errHttp != nil {
		log.Printf("    ERROR: Executing re-register/update request for job %s: %v", jobID, errHttp)
		return
	}
	defer resp.Body.Close()

	respBodyBytes, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var regResp NomadJobRegisterResponse
		if errJson := json.Unmarshal(respBodyBytes, &regResp); errJson == nil {
			log.Printf("    Successfully submitted updated spec for job %s. EvalID: %s, Warnings: %s", jobID, regResp.EvalID, regResp.Warnings)
		} else {
			log.Printf("    Successfully submitted updated spec for job %s (status OK, but could not parse response: %v). Body: %s", jobID, errJson, string(respBodyBytes))
		}
		// User's requested sleep
		log.Printf("    Adding 3 second delay after successful job submission for %s.", jobID)
		time.Sleep(3 * time.Second)
	} else {
		log.Printf("    Failed to submit updated spec for job %s: Status Code %d, Response: %s", jobID, resp.StatusCode, string(respBodyBytes))
	}
}

// updateJobStatusMap updates the shared BPF map.
func updateJobStatusMap(status uint8) {
	statusLock.Lock()
	defer statusLock.Unlock()

	if jobStatusMap == nil {
		log.Println("WARN: jobStatusMap is nil in updateJobStatusMap")
		return
	}

	var currentVal uint8
	// Check current value without lock first for potential early exit (optional optimization)
	// err := jobStatusMap.Lookup(statusMapKey, &currentVal)
	// if err == nil && currentVal == status {
	//  return // Already the desired state
	// }

	// Update the map
	err := jobStatusMap.Update(statusMapKey, status, ebpf.UpdateAny)
	if err != nil {
		log.Printf("ERROR: Failed to update BPF job_status_map to %d: %v", status, err)
	} else {
		statusStr := "REJECT (0)"
		if status == 1 {
			statusStr = "ALLOW (1)"
		}
		// Check current value *after* update to confirm
		errLookup := jobStatusMap.Lookup(statusMapKey, &currentVal)
		if errLookup == nil && currentVal == status {
			log.Printf("INFO: Updated BPF job_status_map: status=%s", statusStr)
		} else if errLookup != nil {
			log.Printf("INFO: Updated BPF job_status_map to %s (confirmation lookup failed: %v)", statusStr, errLookup)
		} else {
			log.Printf("WARN: Updated BPF job_status_map to %s, but confirmation lookup shows different value: %d", statusStr, currentVal)
		}
	}
}

// --- Main Function --- (Updated log message for new delay)
func main() {
	var ifaceName string
	var targetPort uint
	flag.StringVar(&ifaceName, "iface", "lo", "Network interface to attach TC hook")
	flag.UintVar(&targetPort, "port", 4432, "TCP destination port to filter")
	flag.Parse()

	if targetPort == 0 || targetPort > 65535 {
		log.Fatalf("Invalid target port: %d. Must be between 1 and 65535.", targetPort)
	}

	// --- Nomad Config ---
	nomadAddr = os.Getenv("NOMAD_ADDR")
	nomadToken = os.Getenv("NOMAD_TOKEN")
	if nomadAddr == "" {
		nomadAddr = "http://127.0.0.1:4646" // Default Nomad address
		log.Println("WARN: NOMAD_ADDR environment variable not set, defaulting to", nomadAddr)
	}
	if nomadToken == "" {
		log.Println("INFO: NOMAD_TOKEN environment variable not set. Proceeding without authentication token.")
	}
	log.Printf("Nomad Watcher starting. Iface: %s, Port: %d, Task: '%s', Hook: '%s', PostHookDelay: %s, PollInterval: %s, AdditionalGrace: %s",
		ifaceName, targetPort, mainTaskName, targetHookName, postHookCompletionDelay, pollHealthyInterval, additionalRejectionGracePeriod) // Added AdditionalGrace
	log.Printf("  Nomad API: %s, Token Used: %t", nomadAddr, nomadToken != "")

	// --- Increase Memory Lock Limit (Required for BPF) ---
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock limit (RLIMIT_MEMLOCK): %v", err)
	}
	log.Println("Removed memory lock limit.")

	// --- Load BPF Objects ---
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed loading BPF objects: %v", err)
	}
	defer objs.Close() // Ensure BPF resources are cleaned up

	// Verify required maps and programs are present
	if objs.TcIngress == nil {
		log.Fatal("BPF program 'tc_ingress' not found.")
	}
	if objs.ConfigMap == nil {
		log.Fatal("BPF map 'config_map' not found.")
	}
	if objs.JobStatusMap == nil {
		log.Fatal("BPF map 'job_status_map' not found.")
	}
	if objs.Rb == nil {
		log.Fatal("BPF map (ring buffer) 'rb' not found.")
	}
	log.Println("Loaded BPF program (tc_ingress) and maps (config_map, job_status_map, rb)")
	jobStatusMap = objs.JobStatusMap // Assign to global variable

	// --- Configure BPF Maps ---
	// Set target port in config_map
	configMapKey := uint32(0) // Assuming key 0 for port config
	configMapValue := uint16(targetPort)
	if err := objs.ConfigMap.Update(configMapKey, configMapValue, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update BPF config_map with port %d: %v", targetPort, err)
	}
	log.Printf("Updated BPF config_map: key=%d, port=%d", configMapKey, configMapValue)

	// Initialize job_status_map to ALLOW (default state before first SNI triggers checks)
	log.Println("Initializing BPF job_status_map to ALLOW (1)...")
	updateJobStatusMap(1) // Initial state is ALLOW

	// --- Attach BPF Program to TC Hook Point ---
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed getting interface '%s': %v", ifaceName, err)
	}
	log.Printf("Found interface %s (Index: %d)", ifaceName, iface.Attrs().Index)

	// Ensure clsact qdisc is present (required for TC BPF attachments)
	qdiscAttrs := netlink.QdiscAttrs{LinkIndex: iface.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}
	qdisc := &netlink.GenericQdisc{QdiscAttrs: qdiscAttrs, QdiscType: "clsact"}
	if err = netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, os.ErrExist) {
			log.Printf("clsact qdisc already exists on interface %s.", ifaceName)
		} else {
			log.Fatalf("Failed to add clsact qdisc to interface %s: %v", ifaceName, err)
		}
	} else {
		log.Printf("Ensured clsact qdisc is present on interface %s.", ifaceName)
	}

	// Attach the BPF program to the TC ingress hook
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress, // Attach to ingress traffic
		Interface: iface.Attrs().Index,
	})
	if err != nil {
		// Attempt to clean up qdisc if attachment fails? Maybe not, user might have other filters.
		log.Fatalf("Failed attaching BPF program 'tc_ingress' to TC ingress on interface %s: %v", ifaceName, err)
	}
	defer l.Close() // Ensure the link is detached on exit
	log.Printf("Attached BPF program '%s' to TC ingress on %s", objs.TcIngress.String(), ifaceName)

	// --- Set up Ring Buffer Reader ---
	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("Failed creating ring buffer reader for 'rb': %v", err)
	}
	// defer rd.Close() // rd.Close() will be called explicitly during shutdown

	// --- Goroutine for Handling Ring Buffer Events ---
	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel() // Ensure context is cancelled on exit
	var wg sync.WaitGroup

	log.Println("Waiting for events from BPF ring buffer... Press Ctrl+C to exit.")
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("Ring buffer event reader started.")
		for {
			// Check for context cancellation before blocking on Read
			select {
			case <-mainCtx.Done():
				log.Println("Ring buffer reader: main context cancelled. Shutting down.")
				return
			default:
			}

			record, readErr := rd.Read()
			if readErr != nil {
				// Handle expected errors on shutdown
				if errors.Is(readErr, ringbuf.ErrClosed) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, os.ErrClosed) {
					log.Println("Ring buffer closed or context cancelled during read. Exiting reader loop.")
					return
				}
				// Log other errors and attempt to continue (with a small delay)
				log.Printf("WARN: Error reading ring buffer: %v. Retrying shortly...", readErr)
				select {
				case <-mainCtx.Done():
					log.Println("Ring buffer reader stopping after error (context cancelled).")
					return
				case <-time.After(100 * time.Millisecond): // Avoid busy-looping on persistent errors
				}
				continue
			}
			// Process valid records in separate goroutines to avoid blocking the reader loop
			go handleRingbufRecord(mainCtx, record)
		}
	}()

	// --- Graceful Shutdown Handling ---
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	sig := <-stopper // Block until a signal is received
	log.Printf("Received signal %s, initiating shutdown...", sig)

	// 1. Cancel the main context (signals ring buffer reader and pollers to stop)
	log.Println("Stopping background tasks (cancelling main context)...")
	mainCancel()

	// 2. Close the ring buffer reader (unblocks the Read call if it's waiting)
	log.Println("Attempting to close ring buffer reader...")
	if errClose := rd.Close(); errClose != nil {
		log.Printf("Error closing ring buffer reader: %v", errClose)
	} else {
		log.Println("Ring buffer reader closed.")
	}

	// 3. Wait for the ring buffer reader goroutine to finish
	log.Println("Waiting for ring buffer event reader goroutine to finish...")
	wg.Wait()
	log.Println("Ring buffer event reader goroutine finished.")

	// 4. Wait for polling goroutines to shut down (with a timeout)
	shutdownPollTimeout := time.NewTimer(10 * time.Second) // Max wait time for pollers
	pollersStillActive := true
	log.Println("Waiting for polling goroutines to shut down...")

	for pollersStillActive {
		select {
		case <-shutdownPollTimeout.C:
			log.Printf("WARN: Timeout waiting for all pollers to shut down.")
			pollingJobsLock.Lock()
			activeCount := len(pollingJobs)
			if activeCount > 0 {
				log.Printf("WARN: %d polling goroutine(s) may still be active after timeout:", activeCount)
				for jobID := range pollingJobs {
					log.Printf("  - Poller for %s still listed in map.", jobID)
					// Optionally, try to cancel them again forcefully?
					// if cancel, ok := pollingJobs[jobID]; ok { cancel() }
				}
			}
			pollingJobsLock.Unlock()
			pollersStillActive = false // Exit loop after timeout
		default:
			pollingJobsLock.Lock()
			if len(pollingJobs) == 0 {
				log.Println("All polling goroutines have shut down.")
				pollersStillActive = false // Exit loop, all pollers done
			}
			pollingJobsLock.Unlock()
			if pollersStillActive {
				time.Sleep(200 * time.Millisecond) // Check again shortly
			}
		}
	}
	// Clean up the shutdown timer
	if !shutdownPollTimeout.Stop() {
		// Drain channel if Stop returns false (timer already fired)
		select {
		case <-shutdownPollTimeout.C:
		default:
		}
	}

	// 5. BPF link and objects are closed by their defers.

	log.Println("Shutdown complete.")
}
