// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ise // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/ise"

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/ciscoosreceiver/internal/httpclient"
)

const (
	defaultDataConnectRowLimit = 5000

	// Data Connect queries are against fixed, documented views. A result with
	// hundreds of columns is malformed and can otherwise amplify the per-row
	// scan and map allocations before the configured row limit is reached.
	maxDataConnectResultColumns = 256

	// Keep SQL result retention aligned with the aggregate REST pagination
	// ceiling. These limits are deliberately not user-configurable.
	maxDataConnectRetainedBytes       = httpclient.HardMaxPaginationBytes
	dataConnectRetainedRowOverhead    = 64
	dataConnectRetainedFieldOverhead  = 64
	dataConnectRetainedTimeValueBytes = 64
)

var dataConnectViewNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// DataConnectConfig controls Cisco ISE Data Connect database access.
type DataConnectConfig struct {
	Host               string
	Port               int
	ServiceName        string
	Username           string
	Password           string
	WalletDir          string
	SSL                bool
	SSLVerify          bool
	Lookback           time.Duration
	RowLimit           int
	FullViews          bool
	AdditionalReadOnly []string
}

// DataConnectView describes one allowlisted read-only Cisco ISE Data Connect view.
type DataConnectView struct {
	Name       string
	Category   string
	MaxResults int
	TimeColumn string
}

// DataConnectStat describes one Data Connect query.
type DataConnectStat struct {
	View     string
	Outcome  string
	Rows     int
	Duration time.Duration
	Err      error
}

// DataConnectResultLimitError reports that a query returned partial rows
// because retaining more of the result would exceed a hard safety ceiling.
type DataConnectResultLimitError struct {
	Kind     string
	Maximum  int
	Observed int
	Rows     int
}

func (e *DataConnectResultLimitError) Error() string {
	return fmt.Sprintf(
		"scan Data Connect result: hard %s limit of %d exceeded (observed %d) after %d complete rows",
		e.Kind,
		e.Maximum,
		e.Observed,
		e.Rows,
	)
}

// DataConnectClient is a read-only Cisco ISE Data Connect client.
type DataConnectClient struct {
	db        *sql.DB
	rowLimit  int
	lookback  time.Duration
	sslVerify bool

	OnQuery func(DataConnectStat)
}

// NewDataConnectClient creates a Data Connect client.
func NewDataConnectClient(cfg DataConnectConfig) (*DataConnectClient, error) {
	if cfg.Host == "" || cfg.ServiceName == "" || cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("Data Connect host, service name, username, and password are required")
	}
	if !cfg.SSL {
		return nil, errors.New("Data Connect SSL must be enabled because database credentials require TLS")
	}
	rowLimit := cfg.RowLimit
	if rowLimit <= 0 {
		rowLimit = defaultDataConnectRowLimit
	}
	options := map[string]string{}
	if cfg.SSL {
		options["SSL"] = "enable"
	}
	if !cfg.SSLVerify {
		options["SSL VERIFY"] = "false"
	}
	if cfg.WalletDir != "" {
		options["WALLET"] = cfg.WalletDir
	}
	dsn := go_ora.BuildUrl(cfg.Host, cfg.Port, cfg.ServiceName, cfg.Username, cfg.Password, options)
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return nil, err
	}
	return &DataConnectClient{db: db, rowLimit: rowLimit, lookback: cfg.Lookback, sslVerify: cfg.SSLVerify}, nil
}

// Close closes the underlying database handle.
func (c *DataConnectClient) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Ping verifies Data Connect connectivity.
func (c *DataConnectClient) Ping(ctx context.Context) error {
	return c.decorateCertificateVerificationError(c.db.PingContext(ctx))
}

func (c *DataConnectClient) decorateCertificateVerificationError(err error) error {
	if err == nil || !c.sslVerify {
		return err
	}
	return httpclient.DecorateCertificateVerificationErrorWithValue(
		err,
		"ise.data_connect.wallet_dir",
		"ise.data_connect.ssl_verify",
		"false",
	)
}

// QueryView returns rows from one allowlisted Data Connect view.
func (c *DataConnectClient) QueryView(ctx context.Context, view DataConnectView) ([]Object, error) {
	if !ValidDataConnectViewName(view.Name) || IsInternalDataConnectView(view.Name) {
		return nil, fmt.Errorf("Data Connect view %q is not allowlisted", view.Name)
	}
	limit := c.rowLimit
	if view.MaxResults > 0 && view.MaxResults < limit {
		limit = view.MaxResults
	}
	if limit <= 0 {
		limit = defaultDataConnectRowLimit
	}
	viewName := strings.ToUpper(view.Name)
	timeColumn := strings.ToUpper(strings.TrimSpace(view.TimeColumn))
	if timeColumn != "" && !ValidDataConnectViewName(timeColumn) {
		return nil, fmt.Errorf("Data Connect time column %q is not allowlisted", view.TimeColumn)
	}
	var (
		query string
		args  []any
	)
	switch {
	case timeColumn != "" && c.lookback > 0:
		query = fmt.Sprintf("SELECT * FROM %s WHERE %s >= :1 ORDER BY %s DESC FETCH FIRST %d ROWS ONLY", viewName, timeColumn, timeColumn, limit)
		args = append(args, time.Now().UTC().Add(-c.lookback))
	case timeColumn != "":
		query = fmt.Sprintf("SELECT * FROM %s ORDER BY %s DESC FETCH FIRST %d ROWS ONLY", viewName, timeColumn, limit)
	default:
		query = fmt.Sprintf("SELECT * FROM %s FETCH FIRST %d ROWS ONLY", viewName, limit)
	}
	start := time.Now()
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		err = c.decorateCertificateVerificationError(err)
		c.record(DataConnectStat{View: view.Name, Outcome: "error", Duration: time.Since(start), Err: err})
		return nil, err
	}
	defer rows.Close()
	objects, err := scanRows(rows)
	if err != nil {
		err = c.decorateCertificateVerificationError(err)
		c.record(DataConnectStat{View: view.Name, Outcome: "error", Rows: len(objects), Duration: time.Since(start), Err: err})
		return objects, err
	}
	c.record(DataConnectStat{View: view.Name, Outcome: "success", Rows: len(objects), Duration: time.Since(start)})
	return objects, nil
}

func (c *DataConnectClient) record(stat DataConnectStat) {
	if c.OnQuery != nil {
		c.OnQuery(stat)
	}
}

func scanRows(rows *sql.Rows) ([]Object, error) {
	return scanRowsWithBudget(rows, newDataConnectResultBudget())
}

func scanRowsWithBudget(rows *sql.Rows, budget *dataConnectResultBudget) ([]Object, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(columns) > maxDataConnectResultColumns {
		return nil, &DataConnectResultLimitError{
			Kind:     "column count",
			Maximum:  maxDataConnectResultColumns,
			Observed: len(columns),
		}
	}
	if err := budget.charge(columnMetadataRetainedBytes(columns), 0); err != nil {
		return nil, err
	}
	var objects []Object
	for rows.Next() {
		values := make([]dataConnectValueScanner, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return objects, err
		}
		obj, err := normalizeDataConnectRow(columns, values, budget, len(objects))
		if err != nil {
			return objects, err
		}
		objects = append(objects, obj)
	}
	if err := rows.Err(); err != nil {
		return objects, err
	}
	return objects, nil
}

// dataConnectValueScanner retains the driver's value only until the current
// row has been budgeted and normalized. In particular, database/sql does not
// clone []byte into a custom Scanner, allowing the budget check to run before
// the conversion to an owned string.
type dataConnectValueScanner struct {
	value any
}

func (s *dataConnectValueScanner) Scan(src any) error {
	s.value = src
	return nil
}

type dataConnectResultBudget struct {
	maximum int
	used    int
}

func newDataConnectResultBudget() *dataConnectResultBudget {
	return &dataConnectResultBudget{maximum: maxDataConnectRetainedBytes}
}

func (b *dataConnectResultBudget) charge(amount, completeRows int) error {
	if amount < 0 || b.used > b.maximum || amount > b.maximum-b.used {
		return &DataConnectResultLimitError{
			Kind:     "retained byte",
			Maximum:  b.maximum,
			Observed: saturatingDataConnectAdd(b.used, amount),
			Rows:     completeRows,
		}
	}
	b.used += amount
	return nil
}

func columnMetadataRetainedBytes(columns []string) int {
	total := 0
	for _, column := range columns {
		total = cappedDataConnectAdd(total, len(column))
	}
	return total
}

func normalizeDataConnectRow(columns []string, values []dataConnectValueScanner, budget *dataConnectResultBudget, completeRows int) (Object, error) {
	rowBytes := dataConnectRetainedRowOverhead
	for i, column := range columns {
		valueBytes, err := dataConnectValueRetainedBytes(values[i].value)
		if err != nil {
			return nil, fmt.Errorf("scan Data Connect column %q: %w", column, err)
		}
		rowBytes = cappedDataConnectAdd(rowBytes, dataConnectRetainedFieldOverhead)
		rowBytes = cappedDataConnectAdd(rowBytes, len(column))
		rowBytes = cappedDataConnectAdd(rowBytes, valueBytes)
	}
	if err := budget.charge(rowBytes, completeRows); err != nil {
		return nil, err
	}

	obj := make(Object, len(columns))
	for i, column := range columns {
		obj[column] = normalizeDBValue(values[i].value)
	}
	return obj, nil
}

func dataConnectValueRetainedBytes(value any) (int, error) {
	switch typed := value.(type) {
	case nil:
		return 0, nil
	case []byte:
		return len(typed), nil
	case string:
		return len(typed), nil
	case time.Time:
		return dataConnectRetainedTimeValueBytes, nil
	case bool:
		return 1, nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return 8, nil
	default:
		return 0, fmt.Errorf("unsupported database value type %T", value)
	}
}

func cappedDataConnectAdd(total, addition int) int {
	if addition < 0 || total > maxDataConnectRetainedBytes || addition > maxDataConnectRetainedBytes-total {
		return maxDataConnectRetainedBytes + 1
	}
	return total + addition
}

func saturatingDataConnectAdd(left, right int) int {
	if right < 0 || left > maxDataConnectRetainedBytes || right > maxDataConnectRetainedBytes-left {
		return maxDataConnectRetainedBytes + 1
	}
	return left + right
}

func normalizeDBValue(value any) any {
	switch typed := value.(type) {
	case []byte:
		return string(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano)
	default:
		return typed
	}
}

// ValidDataConnectViewName reports whether view is a safe SQL identifier.
func ValidDataConnectViewName(view string) bool {
	return dataConnectViewNamePattern.MatchString(strings.ToUpper(strings.TrimSpace(view)))
}

// IsInternalDataConnectView reports whether a view is documented as internal and should not be collected.
func IsInternalDataConnectView(view string) bool {
	switch strings.ToUpper(strings.TrimSpace(view)) {
	case "UPSPOLICY", "UPSPOLICYSET", "UPSPOLICYSET_POLICIES":
		return true
	default:
		return false
	}
}

// DefaultDataConnectViews returns the documented read-only ISE Data Connect view allowlist.
func DefaultDataConnectViews() []DataConnectView {
	return []DataConnectView{
		{Name: "NODE_LIST", Category: "core"},
		{Name: "NETWORK_DEVICES", Category: "core"},
		{Name: "NETWORK_DEVICE_GROUPS", Category: "core"},
		{Name: "POLICY_SETS", Category: "policy"},
		{Name: "OPENAPI_OPERATIONS", Category: "audit", TimeColumn: "LOGGED_AT"},
		{Name: "ADMINISTRATOR_LOGINS", Category: "audit", TimeColumn: "TIMESTAMP"},
		{Name: "ADMIN_USERS", Category: "audit"},
		{Name: "RADIUS_AUTHENTICATIONS_WEEK", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "RADIUS_ACCOUNTING_WEEK", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "TACACS_AUTHENTICATION_LAST_TWO_DAYS", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_AUTHORIZATION_LAST_TWO_DAYS", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_ACCOUNTING_LAST_TWO_DAYS", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_COMMAND_ACCOUNTING", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "POSTURE_ASSESSMENT_BY_ENDPOINT", Category: "posture", TimeColumn: "TIMESTAMP"},
		{Name: "PROFILED_ENDPOINTS_SUMMARY", Category: "profiler", TimeColumn: "TIMESTAMP"},
		{Name: "PROFILING_POLICIES", Category: "profiler"},
		{Name: "ADAPTIVE_NETWORK_CONTROL", Category: "security", TimeColumn: "LOGGED_AT"},
		{Name: "THREAT_EVENTS", Category: "security", TimeColumn: "LOGGED_AT"},
		{Name: "USER_IDENTITY_GROUPS", Category: "identity"},
	}
}

// FullDataConnectViews returns larger historical views that are only queried when explicitly enabled.
func FullDataConnectViews() []DataConnectView {
	return []DataConnectView{
		{Name: "RADIUS_AUTHENTICATIONS", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "RADIUS_ACCOUNTING", Category: "radius", TimeColumn: "TIMESTAMP"},
		{Name: "TACACS_AUTHENTICATION", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_AUTHORIZATION", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
		{Name: "TACACS_ACCOUNTING", Category: "tacacs", TimeColumn: "LOGGED_TIME"},
	}
}
