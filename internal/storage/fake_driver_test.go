package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
)

// fakeResponse - ответ поддельной базы данных на один запрос: имена колонок и
// строки либо ошибка.
type fakeResponse struct {
	err  error
	cols []string
	rows [][]driver.Value
}

// fakeHandler вычисляет ответ на запрос query с аргументами args.
type fakeHandler func(query string, args []driver.NamedValue) fakeResponse

// fakeDB - поддельная база данных поверх database/sql без сети. Запоминает
// все выполненные запросы, что позволяет проверять порядок и аргументы.
type fakeDB struct {
	handler fakeHandler
	queries []string
	args    [][]driver.NamedValue
	mu      sync.Mutex
}

// open возвращает *sql.DB, все запросы которого обслуживает handler.
func (f *fakeDB) open() *sql.DB {
	return sql.OpenDB(fakeConnector{db: f})
}

// record запоминает выполненный запрос.
func (f *fakeDB) record(query string, args []driver.NamedValue) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.queries = append(f.queries, query)
	f.args = append(f.args, args)
}

// executed возвращает копию списка выполненных запросов.
func (f *fakeDB) executed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.queries...)
}

type fakeConnector struct{ db *fakeDB }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeConn{db: c.db}, nil
}

func (c fakeConnector) Driver() driver.Driver { return fakeDriver(c) }

type fakeDriver struct{ db *fakeDB }

func (d fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{db: d.db}, nil }

type fakeConn struct{ db *fakeDB }

var (
	_ driver.QueryerContext = (*fakeConn)(nil)
	_ driver.ExecerContext  = (*fakeConn)(nil)
)

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("fakeConn: Prepare не поддерживается")
}

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) Begin() (driver.Tx, error) {
	return nil, errors.New("fakeConn: транзакции не поддерживаются")
}

func (c *fakeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.db.record(query, args)

	resp := c.db.handler(query, args)
	if resp.err != nil {
		return nil, resp.err
	}

	return &fakeRows{cols: resp.cols, rows: resp.rows}, nil
}

func (c *fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.db.record(query, args)

	resp := c.db.handler(query, args)
	if resp.err != nil {
		return nil, resp.err
	}

	return driver.RowsAffected(len(resp.rows)), nil
}

type fakeRows struct {
	cols []string
	rows [][]driver.Value
	pos  int
}

func (r *fakeRows) Columns() []string { return r.cols }

func (r *fakeRows) Close() error { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}

	copy(dest, r.rows[r.pos])
	r.pos++

	return nil
}
