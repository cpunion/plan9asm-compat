package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "turso.tech/database/tursogo"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	directory, err := os.MkdirTemp("", "turso-assembly-issue2707-")
	check(err)
	defer os.RemoveAll(directory)

	db, err := sql.Open("turso", filepath.Join(directory, "probe.db"))
	check(err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	check(db.PingContext(ctx))
	_, err = db.ExecContext(ctx, "CREATE TABLE assembly_probe (id INTEGER PRIMARY KEY, value INTEGER)")
	check(err)
	_, err = db.ExecContext(ctx, "INSERT INTO assembly_probe VALUES (?, ?), (?, ?)", 1, 17, 2, 25)
	check(err)

	tx, err := db.BeginTx(ctx, nil)
	check(err)
	_, err = tx.ExecContext(ctx, "INSERT INTO assembly_probe VALUES (?, ?)", 3, 99)
	check(err)
	check(tx.Rollback())

	var count, total int64
	check(db.QueryRowContext(ctx, "SELECT COUNT(*), SUM(value) FROM assembly_probe").Scan(&count, &total))
	if count != 2 || total != 42 {
		panic(fmt.Sprintf("Turso SQL and rollback: count=%d total=%d", count, total))
	}
	check(db.Close())
	fmt.Println("Turso native database query and rollback verified")
}
