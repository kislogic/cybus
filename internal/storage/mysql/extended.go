package mysql

import (
	"context"
	"database/sql"
)

// Queryer is an interface used for selection queries.
type Queryer interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// Execer is an interface used for executing queries.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// ExtendedDB is a union interface which can query, and exec, with Context.
type ExtendedDB interface {
	Queryer
	Execer
}
