// shelley-otel-scraper polls a Shelley SQLite DB read-only and emits one
// OTLP span per assistant message, mapping shelley conversations to OTel
// traces (one trace per conversation, one span per LLM turn).
//
// Designed as a sidecar: the scraper holds NO GCP credentials. It dials an
// OTLP gRPC endpoint — typically your existing auth proxy, which terminates
// the connection, attaches Google credentials, and forwards to Cloud Trace
// (telemetry.googleapis.com). The scraper itself only needs read access to
// shelley.db on disk.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// GenAI semantic-convention attribute keys. Kept as string constants so we
// aren't pinned to a specific semconv package version while the spec churns.
const (
	attrGenAISystem            = "gen_ai.system"
	attrGenAIOperationName     = "gen_ai.operation.name"
	attrGenAIRequestModel      = "gen_ai.request.model"
	attrGenAIResponseModel     = "gen_ai.response.model"
	attrGenAIUsageInputTokens  = "gen_ai.usage.input_tokens"
	attrGenAIUsageOutputTokens = "gen_ai.usage.output_tokens"

	// Shelley-specific extensions.
	attrShelleyConversationID    = "shelley.conversation_id"
	attrShelleyMessageID         = "shelley.message_id"
	attrShelleyMessageSequence   = "shelley.message_sequence"
	attrShelleyCacheReadTokens   = "gen_ai.usage.cache_read_input_tokens"
	attrShelleyCacheCreateTokens = "gen_ai.usage.cache_creation_input_tokens"
	attrShelleyCostUSD           = "gen_ai.usage.cost_usd"
)

type usageRow struct {
	RowID             int64
	MessageID         string
	ConversationID    string
	SequenceID        int64
	CreatedAt         string
	Model             string
	InputTokens       int64
	OutputTokens      int64
	CacheCreateTokens int64
	CacheReadTokens   int64
	CostUSD           float64
	StartTime         *time.Time
	EndTime           *time.Time
}

type state struct {
	LastRowID int64 `json:"last_rowid"`
}

func main() {
	var (
		dbPath       string
		otlpEndpoint string
		otlpInsecure bool
		otlpHeaders  string
		statePath    string
		pollInterval time.Duration
		batchSize    int
		serviceName  string
	)
	flag.StringVar(&dbPath, "db", "shelley.db", "path to Shelley SQLite database (opened read-only)")
	flag.StringVar(&otlpEndpoint, "otlp-endpoint", "localhost:4317", "OTLP gRPC endpoint (your auth proxy, or an OTel Collector that fans to Cloud Trace)")
	flag.BoolVar(&otlpInsecure, "otlp-insecure", false, "skip TLS when dialing the OTLP endpoint (local dev only)")
	flag.StringVar(&otlpHeaders, "otlp-headers", "", "comma-separated KEY=VALUE pairs sent as OTLP metadata (e.g. proxy bearer token)")
	flag.StringVar(&statePath, "state", "/var/lib/shelley-otel-scraper/state.json", "path to local state file (tracks high-water mark)")
	flag.DurationVar(&pollInterval, "interval", 5*time.Second, "DB poll interval")
	flag.IntVar(&batchSize, "batch", 500, "max rows per poll cycle")
	flag.StringVar(&serviceName, "service", "shelley", "service.name resource attribute")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=journal_mode(WAL)&_pragma=busy_timeout(2000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logger.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		logger.Error("ping db", "err", err)
		os.Exit(1)
	}

	exporter, err := newExporter(ctx, otlpEndpoint, otlpInsecure, parseHeaders(otlpHeaders))
	if err != nil {
		logger.Error("init OTLP exporter", "err", err)
		os.Exit(1)
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithHost(),
	)
	if err != nil {
		logger.Error("init resource", "err", err)
		os.Exit(1)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithIDGenerator(&ctxIDGenerator{}),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = tp.Shutdown(shutdownCtx)
	}()
	otel.SetTracerProvider(tp)
	tracer := tp.Tracer("shelley-otel-scraper")

	st, err := loadState(statePath)
	if err != nil {
		logger.Error("load state", "err", err)
		os.Exit(1)
	}
	logger.Info("scraper starting", "db", dbPath, "endpoint", otlpEndpoint, "last_rowid", st.LastRowID)

	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	for {
		emitted, lastID, err := scrape(ctx, db, tracer, st.LastRowID, batchSize)
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("scrape", "err", err)
		}
		if emitted > 0 {
			st.LastRowID = lastID
			if err := saveState(statePath, st); err != nil {
				logger.Error("save state", "err", err)
			} else {
				logger.Info("emitted spans", "count", emitted, "last_rowid", lastID)
			}
		}
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return
		case <-tick.C:
		}
	}
}

const scrapeSQL = `
SELECT
    m.rowid,
    m.message_id,
    m.conversation_id,
    COALESCE(m.sequence_id, 0),
    m.created_at,
    COALESCE(json_extract(m.usage_data, '$.model'), ''),
    COALESCE(json_extract(m.usage_data, '$.input_tokens'), 0),
    COALESCE(json_extract(m.usage_data, '$.output_tokens'), 0),
    COALESCE(json_extract(m.usage_data, '$.cache_creation_input_tokens'), 0),
    COALESCE(json_extract(m.usage_data, '$.cache_read_input_tokens'), 0),
    COALESCE(json_extract(m.usage_data, '$.cost_usd'), 0.0),
    json_extract(m.usage_data, '$.start_time'),
    json_extract(m.usage_data, '$.end_time')
FROM messages m
WHERE m.rowid > ?
  AND m.usage_data IS NOT NULL
  AND m.usage_data != '{}'
  AND COALESCE(json_extract(m.usage_data, '$.output_tokens'), 0) > 0
ORDER BY m.rowid ASC
LIMIT ?
`

func scrape(ctx context.Context, db *sql.DB, tracer trace.Tracer, after int64, limit int) (int, int64, error) {
	rows, err := db.QueryContext(ctx, scrapeSQL, after, limit)
	if err != nil {
		return 0, after, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	last := after
	n := 0
	for rows.Next() {
		var r usageRow
		var startStr, endStr sql.NullString
		if err := rows.Scan(
			&r.RowID, &r.MessageID, &r.ConversationID, &r.SequenceID, &r.CreatedAt,
			&r.Model, &r.InputTokens, &r.OutputTokens, &r.CacheCreateTokens, &r.CacheReadTokens,
			&r.CostUSD, &startStr, &endStr,
		); err != nil {
			return n, last, fmt.Errorf("scan: %w", err)
		}
		if startStr.Valid {
			if t, err := time.Parse(time.RFC3339Nano, startStr.String); err == nil {
				r.StartTime = &t
			}
		}
		if endStr.Valid {
			if t, err := time.Parse(time.RFC3339Nano, endStr.String); err == nil {
				r.EndTime = &t
			}
		}
		emitSpan(ctx, tracer, &r)
		last = r.RowID
		n++
	}
	return n, last, rows.Err()
}

func emitSpan(parentCtx context.Context, tracer trace.Tracer, r *usageRow) {
	traceID := traceIDFor(r.ConversationID)
	ctx := context.WithValue(parentCtx, ctxTraceIDKey{}, traceID)

	start := time.Now().UTC()
	if r.StartTime != nil {
		start = *r.StartTime
	}
	end := start.Add(time.Millisecond)
	if r.EndTime != nil && r.EndTime.After(start) {
		end = *r.EndTime
	}

	_, span := tracer.Start(ctx, "llm.chat",
		trace.WithTimestamp(start),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithNewRoot(),
	)
	span.SetAttributes(
		attribute.String(attrGenAISystem, providerForModel(r.Model)),
		attribute.String(attrGenAIOperationName, "chat"),
		attribute.String(attrGenAIRequestModel, r.Model),
		attribute.String(attrGenAIResponseModel, r.Model),
		attribute.Int64(attrGenAIUsageInputTokens, r.InputTokens),
		attribute.Int64(attrGenAIUsageOutputTokens, r.OutputTokens),
		attribute.Int64(attrShelleyCacheCreateTokens, r.CacheCreateTokens),
		attribute.Int64(attrShelleyCacheReadTokens, r.CacheReadTokens),
		attribute.Float64(attrShelleyCostUSD, r.CostUSD),
		attribute.String(attrShelleyConversationID, r.ConversationID),
		attribute.String(attrShelleyMessageID, r.MessageID),
		attribute.Int64(attrShelleyMessageSequence, r.SequenceID),
	)
	span.End(trace.WithTimestamp(end))
}

// ctxIDGenerator returns the trace ID stashed in context (so emitted spans
// inherit a deterministic per-conversation trace ID derived from
// conversation_id). Span IDs are random.
type ctxIDGenerator struct{}

type ctxTraceIDKey struct{}

func (g *ctxIDGenerator) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	var tid trace.TraceID
	if v, ok := ctx.Value(ctxTraceIDKey{}).(trace.TraceID); ok {
		tid = v
	} else {
		_, _ = rand.Read(tid[:])
	}
	var sid trace.SpanID
	_, _ = rand.Read(sid[:])
	return tid, sid
}

func (g *ctxIDGenerator) NewSpanID(_ context.Context, _ trace.TraceID) trace.SpanID {
	var sid trace.SpanID
	_, _ = rand.Read(sid[:])
	return sid
}

// traceIDFor maps a Shelley conversation_id to a stable 128-bit OTel trace ID.
// Hashing keeps it format-agnostic (works whether IDs are ULIDs, UUIDs, etc.)
// and makes the mapping reproducible: same conversation_id always lands on
// the same trace in Cloud Trace.
func traceIDFor(convoID string) trace.TraceID {
	h := sha256.Sum256([]byte("shelley:convo:" + convoID))
	var t trace.TraceID
	copy(t[:], h[:16])
	return t
}

func providerForModel(model string) string {
	switch {
	case strings.HasPrefix(model, "claude"):
		return "anthropic"
	case strings.HasPrefix(model, "gpt"), strings.HasPrefix(model, "o1"), strings.HasPrefix(model, "o3"), strings.HasPrefix(model, "o4"):
		return "openai"
	case strings.HasPrefix(model, "gemini"):
		return "gemini"
	default:
		return "unknown"
	}
}

func newExporter(ctx context.Context, endpoint string, insecure bool, headers map[string]string) (sdktrace.SpanExporter, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	if len(headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(headers))
	}
	if insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	return otlptracegrpc.New(ctx, opts...)
}

func parseHeaders(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	for _, kv := range strings.Split(s, ",") {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[strings.TrimSpace(kv[:i])] = strings.TrimSpace(kv[i+1:])
		}
	}
	return out
}

func loadState(path string) (state, error) {
	var s state
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if len(b) == 0 {
		return s, nil
	}
	return s, json.Unmarshal(b, &s)
}

func saveState(path string, s state) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
