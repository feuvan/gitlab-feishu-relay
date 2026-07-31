// gitlab-feishu-relay receives GitLab project or group webhook events and
// forwards them to a Feishu custom bot as event-specific interactive cards.
// It uses only the Go standard library and supports Feishu signature checks,
// GitLab secret-token validation, retries, and in-memory event deduplication.
//
// Build:
//
//	go build -o gitlab-feishu-relay main.go
//
// Run:
//
//	GITLAB_TOKEN='optional-random-secret' \
//	FEISHU_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/xxx' \
//	FEISHU_SECRET='optional-feishu-signing-secret' \
//	./gitlab-feishu-relay
//
// Optional environment variables:
//
//	ADDR=:8080 MAX_COMMITS=5 RETRIES=2 DEBUG=1
//
// DEBUG=1 logs the request body and internal parsing error when a request is
// rejected with HTTP 400. Request headers and GitLab tokens are not logged.
//
// Self-test:
//
//	SELF_TEST=1 ./gitlab-feishu-relay
//
// Configure GitLab to POST to /webhooks/gitlab and leave the custom webhook
// template empty. If GITLAB_TOKEN is set, configure the same GitLab secret
// token; without it, protect this service at the network or gateway layer.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxBodySize = 2 << 20

type config struct {
	addr          string
	gitlabToken   string
	feishuWebhook string
	feishuSecret  string
	maxCommits    int
	retries       int
	debug         bool
}

type relay struct {
	config config
	client *http.Client
	seen   *deduper
}

type deduper struct {
	mu    sync.Mutex
	items map[string]time.Time
	ttl   time.Duration
}

type event struct {
	ObjectKind        string  `json:"object_kind"`
	EventName         string  `json:"event_name"`
	EventType         string  `json:"event_type"`
	UserName          string  `json:"user_name"`
	User              user    `json:"user"`
	Project           project `json:"project"`
	Group             group   `json:"group"`
	Ref               string  `json:"ref"`
	Before            string
	After             string           `json:"after"`
	CheckoutSHA       string           `json:"checkout_sha"`
	TotalCommitsCount int              `json:"total_commits_count"`
	Commits           []commit         `json:"commits"`
	ObjectAttributes  objectAttributes `json:"object_attributes"`
	Issue             resource         `json:"issue"`
	MergeRequest      resource         `json:"merge_request"`
	Commit            resource         `json:"commit"`
	Snippet           resource         `json:"snippet"`
	Note              resource         `json:"note"`
	Status            string           `json:"status"`
	Environment       string           `json:"environment"`
	EnvironmentTier   string           `json:"environment_tier"`
	ExternalURL       string           `json:"environment_external_url"`
	DeployableURL     string           `json:"deployable_url"`
	CommitURL         string           `json:"commit_url"`
	CommitTitle       string           `json:"commit_title"`
	BuildName         string           `json:"build_name"`
	BuildStage        string           `json:"build_stage"`
	BuildStatus       string           `json:"build_status"`
	BuildFailure      string           `json:"build_failure_reason"`
	BuildDuration     float64          `json:"build_duration"`
	PipelineID        int              `json:"pipeline_id"`
	ProjectName       string           `json:"project_name"`
	Name              string           `json:"name"`
	Path              string           `json:"path"`
	FullPath          string           `json:"full_path"`
	WebURL            string           `json:"web_url"`
	Action            string           `json:"action"`
	Tag               any              `json:"tag"`
	URL               string           `json:"url"`
	Description       string
}

// webhookEnvelope contains only GitLab's documented event discriminators.
// Event-specific payloads are decoded separately because fields with the same
// name can have different documented types, such as release.tag (string) and
// job.tag (boolean), or push.commit.id (SHA string) and job.commit.id (integer).
type webhookEnvelope struct {
	ObjectKind string `json:"object_kind"`
	EventName  string `json:"event_name"`
	EventType  string `json:"event_type"`
}

// jobEvent follows GitLab 19.1's Job Hook payload. In particular, tag is a
// boolean and commit.id is the pipeline ID (an integer), not a commit SHA.
type jobEvent struct {
	ObjectKind    string   `json:"object_kind"`
	Ref           string   `json:"ref"`
	Tag           bool     `json:"tag"`
	BuildName     string   `json:"build_name"`
	BuildStage    string   `json:"build_stage"`
	BuildStatus   string   `json:"build_status"`
	BuildFailure  string   `json:"build_failure_reason"`
	BuildDuration *float64 `json:"build_duration"`
	PipelineID    int      `json:"pipeline_id"`
	ProjectName   string   `json:"project_name"`
	User          user     `json:"user"`
	Project       project  `json:"project"`
	Commit        struct {
		ID      int     `json:"id"`
		Name    *string `json:"name"`
		SHA     string  `json:"sha"`
		Message string  `json:"message"`
		Status  string  `json:"status"`
	} `json:"commit"`
}

// noteEvent follows GitLab 19.1's Note Hook payload. A note can target a
// commit, merge request, issue, or snippet; absent targets remain nil.
type noteEvent struct {
	ObjectKind       string           `json:"object_kind"`
	EventType        string           `json:"event_type"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
	Commit           *resource        `json:"commit"`
	MergeRequest     *resource        `json:"merge_request"`
	Issue            *resource        `json:"issue"`
	Snippet          *resource        `json:"snippet"`
}

// releaseEvent follows GitLab 19.1's Release Hook payload, where tag is the
// released Git tag string rather than the boolean used by Job Hook payloads.
type releaseEvent struct {
	ObjectKind  string  `json:"object_kind"`
	Name        string  `json:"name"`
	Tag         string  `json:"tag"`
	URL         string  `json:"url"`
	Action      string  `json:"action"`
	Description string  `json:"description"`
	Project     project `json:"project"`
}

type pushEvent struct {
	ObjectKind        string   `json:"object_kind"`
	EventName         string   `json:"event_name"`
	UserName          string   `json:"user_name"`
	Project           project  `json:"project"`
	Ref               string   `json:"ref"`
	Before            string   `json:"before"`
	After             string   `json:"after"`
	CheckoutSHA       string   `json:"checkout_sha"`
	TotalCommitsCount int      `json:"total_commits_count"`
	Commits           []commit `json:"commits"`
}

type mergeRequestEvent struct {
	ObjectKind       string           `json:"object_kind"`
	EventType        string           `json:"event_type"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type issueEvent struct {
	ObjectKind       string           `json:"object_kind"`
	EventType        string           `json:"event_type"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type wikiPageEvent struct {
	ObjectKind       string           `json:"object_kind"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type pipelineEvent struct {
	ObjectKind       string           `json:"object_kind"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type deploymentEvent struct {
	ObjectKind      string  `json:"object_kind"`
	Status          string  `json:"status"`
	Environment     string  `json:"environment"`
	EnvironmentTier string  `json:"environment_tier"`
	ExternalURL     string  `json:"environment_external_url"`
	DeployableURL   string  `json:"deployable_url"`
	CommitURL       string  `json:"commit_url"`
	CommitTitle     string  `json:"commit_title"`
	User            user    `json:"user"`
	Project         project `json:"project"`
}

type featureFlagEvent struct {
	ObjectKind       string           `json:"object_kind"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type milestoneEvent struct {
	ObjectKind       string           `json:"object_kind"`
	EventType        string           `json:"event_type"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
	Action           string           `json:"action"`
}

type emojiEvent struct {
	ObjectKind       string           `json:"object_kind"`
	EventType        string           `json:"event_type"`
	User             user             `json:"user"`
	Project          project          `json:"project"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
	Issue            resource         `json:"issue"`
	MergeRequest     resource         `json:"merge_request"`
	Note             resource         `json:"note"`
}

type tokenEvent struct {
	ObjectKind       string           `json:"object_kind"`
	EventName        string           `json:"event_name"`
	Project          project          `json:"project"`
	Group            group            `json:"group"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type vulnerabilityEvent struct {
	ObjectKind       string           `json:"object_kind"`
	ObjectAttributes objectAttributes `json:"object_attributes"`
}

type groupLifecycleEvent struct {
	EventName string `json:"event_name"`
	UserName  string `json:"user_name"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	FullPath  string `json:"full_path"`
	WebURL    string `json:"web_url"`
	GroupName string `json:"group_name"`
	GroupPath string `json:"group_path"`
}

type user struct {
	Name     string `json:"name"`
	Username string `json:"username"`
}

type project struct {
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
}

type group struct {
	Name     string `json:"group_name"`
	Path     string `json:"group_path"`
	FullPath string `json:"full_path"`
}

type resource struct {
	IID          int    `json:"iid"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	State        string `json:"state"`
	URL          string `json:"url"`
	ID           any    `json:"id"`
	Message      string `json:"message"`
	Note         string `json:"note"`
	NoteableType string `json:"noteable_type"`
}

type commit struct {
	ID      string       `json:"id"`
	Title   string       `json:"title"`
	Message string       `json:"message"`
	URL     string       `json:"url"`
	Author  commitAuthor `json:"author"`
}

type commitAuthor struct {
	Name string `json:"name"`
}

type objectAttributes struct {
	IID             int                   `json:"iid"`
	Title           string                `json:"title"`
	Action          string                `json:"action"`
	State           string                `json:"state"`
	Status          string                `json:"status"`
	DetailedStatus  string                `json:"detailed_status"`
	SourceBranch    string                `json:"source_branch"`
	TargetBranch    string                `json:"target_branch"`
	Ref             string                `json:"ref"`
	URL             string                `json:"url"`
	Duration        float64               `json:"duration"`
	Description     string                `json:"description"`
	Note            string                `json:"note"`
	NoteableType    string                `json:"noteable_type"`
	System          bool                  `json:"system"`
	Message         string                `json:"message"`
	Slug            string                `json:"slug"`
	Name            string                `json:"name"`
	Active          bool                  `json:"active"`
	Severity        string                `json:"severity"`
	Confidential    bool                  `json:"confidential"`
	DueDate         string                `json:"due_date"`
	StartDate       string                `json:"start_date"`
	ExpiresAt       string                `json:"expires_at"`
	AwardableType   string                `json:"awardable_type"`
	AwardedOnURL    string                `json:"awarded_on_url"`
	DeployTokenType string                `json:"deploy_token_type"`
	Location        vulnerabilityLocation `json:"location"`
}

type vulnerabilityLocation struct {
	File       string `json:"file"`
	Dependency struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Version string `json:"version"`
	} `json:"dependency"`
}

type card struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Sign      string     `json:"sign,omitempty"`
	MsgType   string     `json:"msg_type"`
	Card      cardDetail `json:"card"`
}

type cardDetail struct {
	Schema string     `json:"schema"`
	Header cardHeader `json:"header"`
	Body   cardBody   `json:"body"`
}

type cardHeader struct {
	Title    cardText `json:"title"`
	Template string   `json:"template"`
}

type cardText struct {
	Tag     string `json:"tag"`
	Content string `json:"content"`
}

type cardBody struct {
	Elements []cardElement `json:"elements"`
}

type cardElement struct {
	Tag       string         `json:"tag"`
	Content   string         `json:"content,omitempty"`
	TextAlign string         `json:"text_align,omitempty"`
	Text      *cardText      `json:"text,omitempty"`
	Type      string         `json:"type,omitempty"`
	Behaviors []cardBehavior `json:"behaviors,omitempty"`
}

type cardBehavior struct {
	Type       string `json:"type"`
	DefaultURL string `json:"default_url"`
}

func main() {
	if os.Getenv("SELF_TEST") == "1" {
		if err := selfTest(); err != nil {
			log.Fatal(err)
		}
		log.Print("self-test passed")
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	app := &relay{
		config: cfg,
		client: &http.Client{Timeout: 8 * time.Second},
		seen:   &deduper{items: make(map[string]time.Time), ttl: 24 * time.Hour},
	}
	if cfg.gitlabToken == "" {
		log.Print("warning: GITLAB_TOKEN is not set; incoming webhook requests are not authenticated")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /webhooks/gitlab", app.handleGitLab)

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("listening on %s", cfg.addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func selfTest() error {
	decodeTests := []string{
		`{"object_kind":"build","tag":false,"build_name":"test","build_duration":null,"commit":{"id":1335,"name":null}}`,
		`{"object_kind":"note","event_type":"note","object_attributes":{"note":"hello","noteable_type":"MergeRequest"},"merge_request":{"id":457,"iid":13,"title":"change"}}`,
		`{"object_kind":"release","name":"v1.0","tag":"v1.0","action":"create"}`,
	}
	for _, body := range decodeTests {
		if _, err := decodeEvent([]byte(body)); err != nil {
			return fmt.Errorf("decode official GitLab payload: %w", err)
		}
	}

	tests := []struct {
		name    string
		payload event
	}{
		{name: "push", payload: event{ObjectKind: "push", Ref: "refs/heads/main", Project: project{Name: "demo", WebURL: "https://gitlab.example/demo"}}},
		{name: "tag", payload: event{ObjectKind: "tag_push", Ref: "refs/tags/v1", Project: project{Name: "demo"}}},
		{name: "issue", payload: event{ObjectKind: "issue", ObjectAttributes: objectAttributes{IID: 1, Title: "bug", State: "opened"}}},
		{name: "work item", payload: event{ObjectKind: "work_item", ObjectAttributes: objectAttributes{IID: 2, Title: "task"}}},
		{name: "note", payload: event{ObjectKind: "note", ObjectAttributes: objectAttributes{Note: "hello", NoteableType: "Issue"}}},
		{name: "merge request", payload: event{ObjectKind: "merge_request", ObjectAttributes: objectAttributes{IID: 3, Title: "change"}}},
		{name: "wiki", payload: event{ObjectKind: "wiki_page", ObjectAttributes: objectAttributes{Title: "home"}}},
		{name: "pipeline", payload: event{ObjectKind: "pipeline", ObjectAttributes: objectAttributes{Status: "success"}}},
		{name: "job", payload: event{ObjectKind: "build", BuildName: "test", BuildStatus: "failed", Commit: resource{ID: float64(1335)}}},
		{name: "deployment", payload: event{ObjectKind: "deployment", Environment: "prod", Status: "success"}},
		{name: "feature flag", payload: event{ObjectKind: "feature_flag", ObjectAttributes: objectAttributes{Name: "flag", Active: true}}},
		{name: "release", payload: event{ObjectKind: "release", Name: "v1", Tag: "v1"}},
		{name: "milestone", payload: event{ObjectKind: "milestone", ObjectAttributes: objectAttributes{Title: "v1"}}},
		{name: "emoji", payload: event{ObjectKind: "emoji", ObjectAttributes: objectAttributes{Name: "thumbsup"}}},
		{name: "access token", payload: event{ObjectKind: "access_token", ObjectAttributes: objectAttributes{Name: "bot", ExpiresAt: "2026-01-01"}}},
		{name: "deploy token", payload: event{ObjectKind: "deploy_token", ObjectAttributes: objectAttributes{Name: "deploy", ExpiresAt: "2026-01-01"}}},
		{name: "vulnerability", payload: event{ObjectKind: "vulnerability", ObjectAttributes: objectAttributes{Title: "CVE", Severity: "high"}}},
		{name: "group member", payload: event{EventName: "user_add_to_group", Group: group{Name: "team"}}},
		{name: "project lifecycle", payload: event{EventName: "project_create", Name: "demo"}},
		{name: "subgroup lifecycle", payload: event{EventName: "subgroup_create", FullPath: "team/sub"}},
	}
	app := &relay{config: config{maxCommits: 5}}
	for _, test := range tests {
		message := app.buildCard(test.payload, "Test Hook")
		if message.MsgType != "interactive" || message.Card.Header.Title.Content == "" || len(message.Card.Body.Elements) == 0 || message.Card.Body.Elements[0].Content == "" {
			return fmt.Errorf("%s rendered an incomplete card", test.name)
		}
		body, err := json.Marshal(message)
		if err != nil || len(body) > 20<<10 {
			return fmt.Errorf("%s rendered an invalid card: size=%d error=%v", test.name, len(body), err)
		}
	}
	return nil
}

func loadConfig() (config, error) {
	cfg := config{
		addr:          envOr("ADDR", ":8080"),
		gitlabToken:   os.Getenv("GITLAB_TOKEN"),
		feishuWebhook: os.Getenv("FEISHU_WEBHOOK"),
		feishuSecret:  os.Getenv("FEISHU_SECRET"),
		maxCommits:    envInt("MAX_COMMITS", 5),
		retries:       envInt("RETRIES", 2),
		debug:         envBool("DEBUG"),
	}
	if cfg.feishuWebhook == "" {
		return config{}, errors.New("FEISHU_WEBHOOK is required")
	}
	if cfg.maxCommits < 0 || cfg.maxCommits > 20 {
		return config{}, errors.New("MAX_COMMITS must be between 0 and 20")
	}
	if cfg.retries < 0 || cfg.retries > 5 {
		return config{}, errors.New("RETRIES must be between 0 and 5")
	}
	return cfg, nil
}

func (app *relay) handleGitLab(writer http.ResponseWriter, request *http.Request) {
	if app.config.gitlabToken != "" && !secureEqual(request.Header.Get("X-Gitlab-Token"), app.config.gitlabToken) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

	eventID := request.Header.Get("X-Gitlab-Event-UUID")
	if eventID == "" {
		eventID = request.Header.Get("Idempotency-Key")
	}
	if eventID != "" && app.seen.has(eventID) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxBodySize))
	if err != nil {
		app.logBadRequest(request, nil, err)
		http.Error(writer, "invalid request body", http.StatusBadRequest)
		return
	}

	payload, err := decodeEvent(body)
	if err != nil {
		app.logBadRequest(request, body, err)
		http.Error(writer, "invalid JSON", http.StatusBadRequest)
		return
	}
	if payload.ObjectKind == "" {
		payload.ObjectKind = payload.EventName
	}

	message := app.buildCard(payload, request.Header.Get("X-Gitlab-Event"))
	if err := app.sendToFeishu(request.Context(), message); err != nil {
		log.Printf("delivery failed event=%q id=%q: %v", payload.ObjectKind, eventID, err)
		http.Error(writer, "delivery failed", http.StatusBadGateway)
		return
	}
	if eventID != "" {
		app.seen.add(eventID)
	}
	log.Printf("delivered event=%q project=%q id=%q", payload.ObjectKind, projectName(payload.Project), eventID)
	writer.WriteHeader(http.StatusNoContent)
}

func decodeEvent(body []byte) (event, error) {
	var envelope webhookEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return event{}, err
	}

	switch envelope.ObjectKind {
	case "push", "tag_push":
		var wire pushEvent
		if err := decodeWire(body, "Push/Tag Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, EventName: wire.EventName, UserName: wire.UserName, Project: wire.Project, Ref: wire.Ref, Before: wire.Before, After: wire.After, CheckoutSHA: wire.CheckoutSHA, TotalCommitsCount: wire.TotalCommitsCount, Commits: wire.Commits}, nil
	case "build":
		var wire jobEvent
		if err := decodeWire(body, "Job Hook", &wire); err != nil {
			return event{}, err
		}
		duration := 0.0
		if wire.BuildDuration != nil {
			duration = *wire.BuildDuration
		}
		return event{
			ObjectKind:    wire.ObjectKind,
			Ref:           wire.Ref,
			BuildName:     wire.BuildName,
			BuildStage:    wire.BuildStage,
			BuildStatus:   wire.BuildStatus,
			BuildFailure:  wire.BuildFailure,
			BuildDuration: duration,
			PipelineID:    wire.PipelineID,
			ProjectName:   wire.ProjectName,
			User:          wire.User,
			Project:       wire.Project,
		}, nil
	case "note":
		var wire noteEvent
		if err := decodeWire(body, "Note Hook", &wire); err != nil {
			return event{}, err
		}
		result := event{
			ObjectKind:       wire.ObjectKind,
			EventType:        wire.EventType,
			User:             wire.User,
			Project:          wire.Project,
			ObjectAttributes: wire.ObjectAttributes,
		}
		if wire.Commit != nil {
			result.Commit = *wire.Commit
		}
		if wire.MergeRequest != nil {
			result.MergeRequest = *wire.MergeRequest
		}
		if wire.Issue != nil {
			result.Issue = *wire.Issue
		}
		if wire.Snippet != nil {
			result.Snippet = *wire.Snippet
		}
		return result, nil
	case "release":
		var wire releaseEvent
		if err := decodeWire(body, "Release Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, Name: wire.Name, Tag: wire.Tag, URL: wire.URL, Action: wire.Action, Description: wire.Description, Project: wire.Project}, nil
	case "merge_request":
		var wire mergeRequestEvent
		if err := decodeWire(body, "Merge Request Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, EventType: wire.EventType, User: wire.User, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes}, nil
	case "issue", "work_item":
		var wire issueEvent
		if err := decodeWire(body, "Issue/Work Item Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, EventType: wire.EventType, User: wire.User, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes}, nil
	case "wiki_page":
		var wire wikiPageEvent
		if err := decodeWire(body, "Wiki Page Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, User: wire.User, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes}, nil
	case "pipeline":
		var wire pipelineEvent
		if err := decodeWire(body, "Pipeline Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, User: wire.User, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes}, nil
	case "deployment":
		var wire deploymentEvent
		if err := decodeWire(body, "Deployment Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, Status: wire.Status, Environment: wire.Environment, EnvironmentTier: wire.EnvironmentTier, ExternalURL: wire.ExternalURL, DeployableURL: wire.DeployableURL, CommitURL: wire.CommitURL, CommitTitle: wire.CommitTitle, User: wire.User, Project: wire.Project}, nil
	case "feature_flag":
		var wire featureFlagEvent
		if err := decodeWire(body, "Feature Flag Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, User: wire.User, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes}, nil
	case "milestone":
		var wire milestoneEvent
		if err := decodeWire(body, "Milestone Hook", &wire); err != nil {
			return event{}, err
		}
		wire.ObjectAttributes.Action = firstNonEmpty(wire.ObjectAttributes.Action, wire.Action)
		return event{ObjectKind: wire.ObjectKind, EventType: wire.EventType, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes}, nil
	case "emoji":
		var wire emojiEvent
		if err := decodeWire(body, "Emoji Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, EventType: wire.EventType, User: wire.User, Project: wire.Project, ObjectAttributes: wire.ObjectAttributes, Issue: wire.Issue, MergeRequest: wire.MergeRequest, Note: wire.Note}, nil
	case "access_token", "deploy_token":
		var wire tokenEvent
		if err := decodeWire(body, "Resource Token Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, EventName: wire.EventName, Project: wire.Project, Group: wire.Group, ObjectAttributes: wire.ObjectAttributes}, nil
	case "vulnerability":
		var wire vulnerabilityEvent
		if err := decodeWire(body, "Vulnerability Hook", &wire); err != nil {
			return event{}, err
		}
		return event{ObjectKind: wire.ObjectKind, ObjectAttributes: wire.ObjectAttributes}, nil
	case "":
		var wire groupLifecycleEvent
		if err := decodeWire(body, "Group Lifecycle Hook", &wire); err != nil {
			return event{}, err
		}
		return event{EventName: wire.EventName, UserName: wire.UserName, Name: wire.Name, Path: wire.Path, FullPath: wire.FullPath, WebURL: wire.WebURL, Group: group{Name: wire.GroupName, Path: wire.GroupPath, FullPath: wire.GroupPath}}, nil
	default:
		return event{}, fmt.Errorf("unsupported GitLab webhook event: object_kind=%q event_name=%q event_type=%q", envelope.ObjectKind, envelope.EventName, envelope.EventType)
	}
}

func decodeWire(body []byte, name string, destination any) error {
	if err := json.Unmarshal(body, destination); err != nil {
		return fmt.Errorf("decode GitLab %s: %w", name, err)
	}
	return nil
}

func (app *relay) logBadRequest(request *http.Request, body []byte, err error) {
	if !app.config.debug {
		return
	}
	log.Printf("debug: rejected request method=%s path=%q content_type=%q body=%q error=%v",
		request.Method, request.URL.Path, request.Header.Get("Content-Type"), body, err)
}

func (app *relay) buildCard(payload event, eventHeader string) card {
	title := "GitLab 通知"
	color := "blue"
	buttonText := "在 GitLab 中查看"
	lines := make([]string, 0, 10)
	lines = addField(lines, "项目", projectName(payload.Project), false)
	lines = addField(lines, "触发人", actor(payload), false)
	link := payload.Project.WebURL

	switch payload.ObjectKind {
	case "push", "tag_push":
		branch := strings.TrimPrefix(strings.TrimPrefix(payload.Ref, "refs/heads/"), "refs/tags/")
		isTag := payload.ObjectKind == "tag_push"
		created := allZeros(payload.Before)
		deleted := allZeros(payload.After)
		title = "代码推送"
		if isTag {
			title = "标签推送"
		}
		if created {
			title += " · 创建"
		} else if deleted {
			title += " · 删除"
		}
		lines = addField(lines, map[bool]string{true: "标签", false: "分支"}[isTag], branch, true)
		lines = addField(lines, "提交数", strconv.Itoa(payload.TotalCommitsCount), false)
		limit := min(len(payload.Commits), app.config.maxCommits)
		for index := 0; index < limit; index++ {
			item := payload.Commits[index]
			text := firstNonEmpty(item.Title, firstLine(item.Message), "无标题")
			lines = append(lines, fmt.Sprintf("`%s` %s — %s", shortSHA(item.ID), md(text), md(item.Author.Name)))
		}
		if payload.TotalCommitsCount > limit {
			lines = append(lines, fmt.Sprintf("_另有 %d 条提交未展示_", payload.TotalCommitsCount-limit))
		}
		buttonText = map[bool]string{true: "查看标签", false: "查看提交"}[isTag]
		if payload.CheckoutSHA != "" {
			link = strings.TrimRight(payload.Project.WebURL, "/") + "/-/commit/" + payload.CheckoutSHA
		} else if payload.After != "" && !allZeros(payload.After) {
			link = strings.TrimRight(payload.Project.WebURL, "/") + "/-/commit/" + payload.After
		}
	case "merge_request":
		a := payload.ObjectAttributes
		title = fmt.Sprintf("合并请求 !%d · %s", a.IID, displayAction(firstNonEmpty(a.Action, a.State, "update")))
		lines = append(lines,
			fmt.Sprintf("**标题：** %s", md(a.Title)),
			fmt.Sprintf("**分支：** `%s` → `%s`", md(a.SourceBranch), md(a.TargetBranch)),
			fmt.Sprintf("**当前状态：** %s", md(displayStatus(a.State))),
		)
		lines = addField(lines, "说明", clip(a.Description, 280), false)
		link = firstNonEmpty(a.URL, link)
		buttonText = "查看合并请求"
		if a.Action == "merge" || a.State == "merged" {
			color = "green"
		} else if a.Action == "close" || a.State == "closed" {
			color = "grey"
		}
	case "pipeline":
		a := payload.ObjectAttributes
		status := firstNonEmpty(a.DetailedStatus, a.Status, "unknown")
		title = "流水线 · " + displayStatus(status)
		lines = append(lines,
			fmt.Sprintf("**分支：** `%s`", md(a.Ref)),
			fmt.Sprintf("**状态：** %s", md(displayStatus(status))),
		)
		if a.Duration > 0 {
			lines = append(lines, fmt.Sprintf("**耗时：** %s", formatDuration(a.Duration)))
		}
		link = firstNonEmpty(a.URL, link)
		buttonText = "查看流水线"
		switch a.Status {
		case "success":
			color = "green"
		case "failed", "canceled":
			color = "red"
		case "running", "pending":
			color = "orange"
		}
	case "issue", "work_item":
		a := payload.ObjectAttributes
		kind := firstNonEmpty(a.Name, "议题")
		if payload.ObjectKind == "work_item" {
			kind = "工作项"
		}
		title = fmt.Sprintf("%s #%d · %s", kind, a.IID, displayAction(firstNonEmpty(a.Action, a.State, "update")))
		lines = append(lines,
			fmt.Sprintf("**标题：** %s", md(a.Title)),
			fmt.Sprintf("**状态：** %s", md(displayStatus(a.State))),
		)
		lines = addField(lines, "说明", clip(a.Description, 280), false)
		if a.Severity != "" {
			lines = append(lines, fmt.Sprintf("**严重级别：** %s", md(a.Severity)))
		}
		if a.Confidential {
			lines = append(lines, "**可见性：** 机密")
		}
		link = firstNonEmpty(a.URL, link)
		buttonText = "查看" + kind
		color = actionColor(a.Action, a.State)
	case "note":
		a := payload.ObjectAttributes
		title = noteableName(firstNonEmpty(a.NoteableType, "资源")) + "评论"
		if a.System {
			title += " · 系统"
		}
		lines = append(lines,
			fmt.Sprintf("**对象：** %s", md(noteTarget(payload))),
			fmt.Sprintf("**内容：** %s", md(clip(a.Note, 800))),
		)
		link = firstNonEmpty(a.URL, resourceURL(payload), link)
		buttonText = "查看评论"
	case "wiki_page":
		a := payload.ObjectAttributes
		title = "Wiki 页面 · " + displayAction(firstNonEmpty(a.Action, "update"))
		lines = append(lines,
			fmt.Sprintf("**页面：** %s", md(a.Title)),
			fmt.Sprintf("**说明：** %s", md(firstNonEmpty(a.Message, clip(a.Description, 400), "无"))),
		)
		link = firstNonEmpty(a.URL, link)
		buttonText = "查看 Wiki"
		color = actionColor(a.Action, "")
	case "build":
		title = "Job · " + displayStatus(firstNonEmpty(payload.BuildStatus, "unknown"))
		lines = append(lines,
			fmt.Sprintf("**Job：** %s", md(payload.BuildName)),
			fmt.Sprintf("**阶段：** %s", md(payload.BuildStage)),
			fmt.Sprintf("**分支：** `%s`", md(payload.Ref)),
			fmt.Sprintf("**状态：** %s", md(displayStatus(payload.BuildStatus))),
		)
		if payload.BuildDuration > 0 {
			lines = append(lines, fmt.Sprintf("**耗时：** %s", formatDuration(payload.BuildDuration)))
		}
		if payload.BuildFailure != "" && payload.BuildStatus == "failed" {
			lines = append(lines, fmt.Sprintf("**失败原因：** %s", md(payload.BuildFailure)))
		}
		if payload.PipelineID > 0 && payload.Project.WebURL != "" {
			link = fmt.Sprintf("%s/-/pipelines/%d", strings.TrimRight(payload.Project.WebURL, "/"), payload.PipelineID)
		}
		buttonText = "查看 Job / 流水线"
		color = statusColor(payload.BuildStatus)
	case "deployment":
		title = "部署 · " + displayStatus(firstNonEmpty(payload.Status, "unknown"))
		lines = addField(lines, "环境", payload.Environment, false)
		lines = addField(lines, "环境层级", payload.EnvironmentTier, false)
		lines = addField(lines, "状态", displayStatus(payload.Status), false)
		lines = addField(lines, "提交", payload.CommitTitle, false)
		link = firstNonEmpty(payload.ExternalURL, payload.DeployableURL, payload.CommitURL, link)
		buttonText = "打开部署环境"
		color = statusColor(payload.Status)
	case "feature_flag":
		a := payload.ObjectAttributes
		state := "已关闭"
		if a.Active {
			state = "已开启"
		}
		buttonText = "查看 Feature Flag"
		title = "Feature Flag · " + state
		lines = append(lines,
			fmt.Sprintf("**名称：** `%s`", md(a.Name)),
			fmt.Sprintf("**状态：** %s", state),
			fmt.Sprintf("**说明：** %s", md(firstNonEmpty(a.Description, "无"))),
		)
		if a.Active {
			color = "green"
		} else {
			color = "grey"
		}
	case "release":
		title = "Release · " + displayAction(firstNonEmpty(payload.Action, "update"))
		lines = append(lines,
			fmt.Sprintf("**名称：** %s", md(payload.Name)),
			fmt.Sprintf("**Tag：** `%s`", md(resourceID(payload.Tag))),
		)
		lines = addField(lines, "说明", clip(payload.Description, 320), false)
		link = firstNonEmpty(payload.URL, link)
		buttonText = "查看 Release"
		color = actionColor(payload.Action, "")
	case "milestone":
		a := payload.ObjectAttributes
		title = "里程碑 · " + displayAction(firstNonEmpty(a.Action, a.State, "update"))
		lines = append(lines,
			fmt.Sprintf("**名称：** %s", md(a.Title)),
			fmt.Sprintf("**状态：** %s", md(displayStatus(a.State))),
		)
		if a.StartDate != "" || a.DueDate != "" {
			lines = append(lines, fmt.Sprintf("**周期：** %s ～ %s", md(firstNonEmpty(a.StartDate, "未设置")), md(firstNonEmpty(a.DueDate, "未设置"))))
		}
		link = firstNonEmpty(a.URL, link)
		buttonText = "查看里程碑"
		color = actionColor(a.Action, a.State)
	case "emoji":
		a := payload.ObjectAttributes
		title = "Emoji · " + displayAction(firstNonEmpty(a.Action, "award"))
		lines = append(lines,
			fmt.Sprintf("**表情：** :%s:", md(a.Name)),
			fmt.Sprintf("**对象：** %s", md(a.AwardableType)),
		)
		link = firstNonEmpty(a.AwardedOnURL, resourceURL(payload), link)
		buttonText = "查看表情位置"
	case "access_token", "deploy_token":
		a := payload.ObjectAttributes
		tokenType := "访问令牌"
		if payload.ObjectKind == "deploy_token" {
			tokenType = "部署令牌"
		}
		title = tokenType + "即将到期"
		lines = append(lines,
			fmt.Sprintf("**名称：** %s", md(a.Name)),
			fmt.Sprintf("**到期时间：** %s", md(a.ExpiresAt)),
		)
		if a.DeployTokenType != "" {
			lines = append(lines, fmt.Sprintf("**类型：** %s", md(a.DeployTokenType)))
		}
		color = "orange"
		buttonText = "管理令牌"
	case "vulnerability":
		a := payload.ObjectAttributes
		title = "安全漏洞 · " + displaySeverity(firstNonEmpty(a.Severity, a.State, "unknown"))
		lines = append(lines,
			fmt.Sprintf("**标题：** %s", md(a.Title)),
			fmt.Sprintf("**状态：** %s", md(displayStatus(a.State))),
			fmt.Sprintf("**严重级别：** %s", md(displaySeverity(a.Severity))),
		)
		if a.Location.File != "" {
			lines = append(lines, fmt.Sprintf("**位置：** `%s`", md(a.Location.File)))
		}
		if a.Location.Dependency.Package.Name != "" {
			lines = append(lines, fmt.Sprintf("**依赖：** `%s@%s`", md(a.Location.Dependency.Package.Name), md(a.Location.Dependency.Version)))
		}
		link = firstNonEmpty(a.URL, link)
		color = severityColor(a.Severity)
		buttonText = "查看漏洞详情"
	case "":
		title, lines, link, color = groupEventCard(payload, eventHeader, lines, link)
	default:
		title = firstNonEmpty(eventHeader, payload.ObjectKind, "GitLab 通知")
		lines = append(lines, fmt.Sprintf("**事件：** %s", md(firstNonEmpty(payload.ObjectKind, payload.EventName, eventHeader))))
	}

	elements := []cardElement{{
		Tag:       "markdown",
		Content:   strings.Join(lines, "\n"),
		TextAlign: "left",
	}}
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		elements = append(elements, cardElement{
			Tag:  "button",
			Text: &cardText{Tag: "plain_text", Content: buttonText},
			Type: "default",
			Behaviors: []cardBehavior{{
				Type:       "open_url",
				DefaultURL: link,
			}},
		})
	}

	message := card{
		MsgType: "interactive",
		Card: cardDetail{
			Schema: "2.0",
			Header: cardHeader{
				Title:    cardText{Tag: "plain_text", Content: title},
				Template: color,
			},
			Body: cardBody{Elements: elements},
		},
	}
	if app.config.feishuSecret != "" {
		message.Timestamp = strconv.FormatInt(time.Now().Unix(), 10)
		message.Sign = feishuSign(message.Timestamp, app.config.feishuSecret)
	}
	return message
}

func (app *relay) sendToFeishu(ctx context.Context, message card) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt <= app.config.retries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(1<<(attempt-1)) * 500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodPost, app.config.feishuWebhook, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := app.client.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		closeErr := response.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}

		var result struct {
			Code          int    `json:"code"`
			StatusCode    int    `json:"StatusCode"`
			Msg           string `json:"msg"`
			StatusMessage string `json:"StatusMessage"`
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 && json.Unmarshal(responseBody, &result) == nil && result.Code == 0 && result.StatusCode == 0 {
			return nil
		}
		lastErr = fmt.Errorf("feishu status=%d code=%d message=%q", response.StatusCode, firstNonZero(result.Code, result.StatusCode), firstNonEmpty(result.Msg, result.StatusMessage, string(responseBody)))
		if response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	return lastErr
}

func (cache *deduper) has(key string) bool {
	now := time.Now()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for item, expiry := range cache.items {
		if now.After(expiry) {
			delete(cache.items, item)
		}
	}
	_, ok := cache.items[key]
	return ok
}

func (cache *deduper) add(key string) {
	cache.mu.Lock()
	cache.items[key] = time.Now().Add(cache.ttl)
	cache.mu.Unlock()
}

func feishuSign(timestamp, secret string) string {
	key := timestamp + "\n" + secret
	hash := hmac.New(sha256.New, []byte(key))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func secureEqual(actual, expected string) bool {
	if len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func projectName(value project) string {
	return firstNonEmpty(value.PathWithNamespace, value.Name, "未知项目")
}

func actor(payload event) string {
	return firstNonEmpty(payload.UserName, payload.User.Name, payload.User.Username, "系统")
}

func noteTarget(payload event) string {
	for _, item := range []resource{payload.MergeRequest, payload.Issue, payload.Commit, payload.Snippet, payload.Note} {
		if value := firstNonEmpty(item.Title, item.Message, item.Description, resourceID(item.ID)); value != "" {
			if item.IID > 0 {
				return fmt.Sprintf("#%d %s", item.IID, value)
			}
			return value
		}
	}
	return firstNonEmpty(payload.ObjectAttributes.NoteableType, "未知资源")
}

func resourceID(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func resourceURL(payload event) string {
	for _, item := range []resource{payload.MergeRequest, payload.Issue, payload.Commit, payload.Snippet, payload.Note} {
		if item.URL != "" {
			return item.URL
		}
	}
	return ""
}

func groupEventCard(payload event, eventHeader string, lines []string, link string) (string, []string, string, string) {
	eventName := firstNonEmpty(payload.EventName, payload.EventType)
	resourceName := firstNonEmpty(payload.FullPath, payload.Path, payload.Name, payload.Group.FullPath, payload.Group.Path, payload.Group.Name, "未知资源")
	titles := map[string]string{
		"user_add_to_group":                    "群组成员加入",
		"user_update_for_group":                "群组成员更新",
		"user_remove_from_group":               "群组成员移除",
		"user_access_request_to_group":         "群组访问申请",
		"user_access_request_denied_for_group": "群组访问申请被拒",
		"project_create":                       "项目创建",
		"project_destroy":                      "项目删除",
		"subgroup_create":                      "子组创建",
		"subgroup_destroy":                     "子组删除",
	}
	title := firstNonEmpty(titles[eventName], eventHeader, eventName, "GitLab 通知")
	lines = append(lines,
		fmt.Sprintf("**事件：** %s", md(eventName)),
		fmt.Sprintf("**资源：** %s", md(resourceName)),
	)
	link = firstNonEmpty(payload.WebURL, link)
	color := actionColor(eventName, "")
	return title, lines, link, color
}

func actionColor(action, state string) string {
	value := strings.ToLower(firstNonEmpty(action, state))
	switch {
	case strings.Contains(value, "delete"), strings.Contains(value, "destroy"), value == "close", value == "closed", strings.Contains(value, "remove"), strings.Contains(value, "denied"):
		return "grey"
	case value == "merge", value == "merged", value == "open", value == "opened", value == "create", value == "reopen", strings.Contains(value, "add"):
		return "green"
	default:
		return "blue"
	}
}

func statusColor(status string) string {
	switch strings.ToLower(status) {
	case "success", "passed":
		return "green"
	case "failed", "failure", "canceled", "cancelled":
		return "red"
	case "running", "pending", "created", "preparing", "waiting_for_resource", "manual", "scheduled":
		return "orange"
	case "skipped":
		return "grey"
	default:
		return "blue"
	}
}

func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "red"
	case "medium":
		return "orange"
	case "low", "info", "unknown":
		return "blue"
	default:
		return "grey"
	}
}

func clip(value string, limit int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func addField(lines []string, label, value string, code bool) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return lines
	}
	if code {
		return append(lines, fmt.Sprintf("**%s：** `%s`", label, md(value)))
	}
	return append(lines, fmt.Sprintf("**%s：** %s", label, md(value)))
}

func displayAction(value string) string {
	labels := map[string]string{
		"open": "创建", "create": "创建", "reopen": "重新打开",
		"update": "更新", "close": "关闭", "delete": "删除",
		"merge": "合并", "approval": "批准", "unapproval": "取消批准",
		"approved": "已批准", "unapproved": "已取消批准",
		"award": "添加", "revoke": "移除",
	}
	return firstNonEmpty(labels[strings.ToLower(value)], value)
}

func displayStatus(value string) string {
	labels := map[string]string{
		"created": "已创建", "pending": "等待中", "preparing": "准备中",
		"running": "运行中", "success": "成功", "passed": "通过",
		"failed": "失败", "failure": "失败", "canceled": "已取消",
		"cancelled": "已取消", "skipped": "已跳过", "manual": "等待手动执行",
		"scheduled": "已计划", "opened": "打开", "open": "打开",
		"closed": "关闭", "merged": "已合并", "active": "活跃",
		"confirmed": "已确认", "resolved": "已解决", "dismissed": "已忽略",
		"detected": "已发现", "unknown": "未知",
	}
	return firstNonEmpty(labels[strings.ToLower(value)], value)
}

func displaySeverity(value string) string {
	labels := map[string]string{
		"critical": "严重", "high": "高", "medium": "中",
		"low": "低", "info": "信息", "unknown": "未知",
	}
	return firstNonEmpty(labels[strings.ToLower(value)], value)
}

func noteableName(value string) string {
	labels := map[string]string{
		"Commit": "提交", "MergeRequest": "合并请求", "Issue": "议题", "Snippet": "代码片段",
	}
	return firstNonEmpty(labels[value], value)
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return strings.TrimSpace(line)
}

func shortSHA(value string) string {
	if len(value) > 8 {
		return value[:8]
	}
	return value
}

func allZeros(value string) bool {
	return value != "" && strings.Trim(value, "0") == ""
}

func formatDuration(seconds float64) string {
	return (time.Duration(seconds * float64(time.Second))).Round(time.Second).String()
}

func md(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]")
	return replacer.Replace(value)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("%s must be an integer", key)
	}
	return parsed
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
