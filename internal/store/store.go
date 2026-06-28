package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"bap-web/internal/model"
	"bap-web/internal/random"
	"bap-web/internal/sshkeys"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(driver, dsn string) (*Store, error) {
	if driver != "sqlite" {
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash BLOB NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			csrf_token TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			prefix TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			owner_user_id TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			last_used_at TEXT,
			expires_at TEXT,
			revoked_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS vms (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			state TEXT NOT NULL,
			vcpu_count INTEGER NOT NULL,
			mem_mib INTEGER NOT NULL,
			ssh_port INTEGER NOT NULL UNIQUE,
			tap_name TEXT NOT NULL UNIQUE,
			host_ip TEXT NOT NULL,
			guest_ip TEXT NOT NULL UNIQUE,
			cidr INTEGER NOT NULL,
			kernel_path TEXT NOT NULL,
			kernel_id TEXT NOT NULL DEFAULT '',
			rootfs_path TEXT NOT NULL,
			base_rootfs_path TEXT NOT NULL,
			base_image_id TEXT NOT NULL DEFAULT '',
			rootfs_size_mib INTEGER NOT NULL DEFAULT 0,
			dev_user TEXT NOT NULL,
			ssh_key_id TEXT NOT NULL DEFAULT '',
			managed_ssh_public_key TEXT NOT NULL,
			managed_ssh_private_key_path TEXT NOT NULL,
			extra_authorized_keys TEXT NOT NULL DEFAULT '',
			repo_url TEXT NOT NULL DEFAULT '',
			git_ref TEXT NOT NULL DEFAULT 'HEAD',
			egress_mode TEXT NOT NULL DEFAULT 'allow_all',
			egress_policy_id TEXT NOT NULL DEFAULT '',
			network_mode TEXT NOT NULL DEFAULT 'routed_ptp',
			network_id TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_started_at TEXT,
			last_stopped_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL,
			fingerprint TEXT NOT NULL UNIQUE,
			key_type TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_used_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS networks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			cidr TEXT NOT NULL UNIQUE,
			gateway_ip TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS ingress_rules (
			id TEXT PRIMARY KEY,
			vm_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			host_port INTEGER NOT NULL UNIQUE,
			guest_port INTEGER NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS egress_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			mode TEXT NOT NULL,
			tcp_ports TEXT NOT NULL DEFAULT '',
			udp_ports TEXT NOT NULL DEFAULT '',
			cidrs TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS base_images (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL,
			filesystem TEXT NOT NULL,
			path TEXT NOT NULL UNIQUE,
			virtual_size_mib INTEGER NOT NULL,
			disk_size_bytes INTEGER NOT NULL,
			checksum TEXT NOT NULL,
			packages TEXT NOT NULL DEFAULT '',
			hooks TEXT NOT NULL DEFAULT '',
			provenance TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS image_build_jobs (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			name TEXT NOT NULL,
			filesystem TEXT NOT NULL,
			size_mib INTEGER NOT NULL,
			packages TEXT NOT NULL DEFAULT '',
			hooks TEXT NOT NULL DEFAULT '',
			log_path TEXT NOT NULL DEFAULT '',
			result_image_id TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS image_hooks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			source_type TEXT NOT NULL,
			status TEXT NOT NULL,
			content_path TEXT NOT NULL DEFAULT '',
			git_url TEXT NOT NULL DEFAULT '',
			git_ref TEXT NOT NULL DEFAULT '',
			git_path TEXT NOT NULL DEFAULT '',
			resolved_commit TEXT NOT NULL DEFAULT '',
			checksum TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_used_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS kernels (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			version TEXT NOT NULL DEFAULT '',
			architecture TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			source_type TEXT NOT NULL,
			path TEXT NOT NULL UNIQUE,
			config_path TEXT NOT NULL DEFAULT '',
			checksum TEXT NOT NULL,
			boot_args TEXT NOT NULL DEFAULT '',
			provenance TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_tested_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS kernel_test_jobs (
			id TEXT PRIMARY KEY,
			kernel_id TEXT NOT NULL,
			status TEXT NOT NULL,
			log_path TEXT NOT NULL DEFAULT '',
			base_image_id TEXT NOT NULL DEFAULT '',
			uname_result TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS kernel_discovery_jobs (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			source_url TEXT NOT NULL DEFAULT '',
			ci_prefix TEXT NOT NULL DEFAULT '',
			architecture TEXT NOT NULL DEFAULT '',
			item_count INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS kernel_discovery_items (
			id TEXT PRIMARY KEY,
			job_id TEXT NOT NULL,
			version TEXT NOT NULL,
			variant TEXT NOT NULL DEFAULT '',
			architecture TEXT NOT NULL DEFAULT '',
			ci_prefix TEXT NOT NULL DEFAULT '',
			kernel_key TEXT NOT NULL,
			config_key TEXT NOT NULL DEFAULT '',
			kernel_url TEXT NOT NULL,
			config_url TEXT NOT NULL DEFAULT '',
			already_registered INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS vm_exec_jobs (
			id TEXT PRIMARY KEY,
			vm_id TEXT NOT NULL,
			status TEXT NOT NULL,
			command TEXT NOT NULL,
			cwd TEXT NOT NULL DEFAULT '',
			env_json TEXT NOT NULL DEFAULT '{}',
			pty INTEGER NOT NULL DEFAULT 0,
			timeout_seconds INTEGER NOT NULL DEFAULT 60,
			stdout TEXT NOT NULL DEFAULT '',
			stderr TEXT NOT NULL DEFAULT '',
			exit_code INTEGER NOT NULL DEFAULT -1,
			timed_out INTEGER NOT NULL DEFAULT 0,
			truncated INTEGER NOT NULL DEFAULT 0,
			log_path TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			source TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			outcome TEXT NOT NULL,
			request_id TEXT NOT NULL,
			message TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := s.ensureColumn(ctx, "vms", "ssh_key_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "vms", "egress_policy_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "vms", "base_image_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "vms", "rootfs_size_mib", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "vms", "kernel_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.migrateAPITokens(ctx); err != nil {
		return err
	}
	return s.migrateLegacySSHKeys(ctx)
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt, pk any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+definition)
	return err
}

func (s *Store) migrateAPITokens(ctx context.Context) error {
	if err := s.ensureColumn(ctx, "api_tokens", "owner_user_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE api_tokens
		SET owner_user_id = (
			SELECT users.id FROM users WHERE users.username = api_tokens.created_by
		)
		WHERE owner_user_id = ''
		  AND created_by != ''
		  AND EXISTS (SELECT 1 FROM users WHERE users.username = api_tokens.created_by)
	`); err != nil {
		return err
	}
	hasGlobalNameUnique, err := s.apiTokensHaveGlobalNameUnique(ctx)
	if err != nil {
		return err
	}
	if hasGlobalNameUnique {
		if err := s.rebuildAPITokens(ctx); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS api_tokens_owner_name_idx ON api_tokens(owner_user_id, name)`)
	return err
}

func (s *Store) apiTokensHaveGlobalNameUnique(ctx context.Context) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA index_list(api_tokens)`)
	if err != nil {
		return false, err
	}
	type indexInfo struct {
		name   string
		unique bool
	}
	indexes := []indexInfo{}
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			rows.Close()
			return false, err
		}
		indexes = append(indexes, indexInfo{name: name, unique: unique == 1})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, index := range indexes {
		if !index.unique {
			continue
		}
		cols, err := s.indexColumns(ctx, index.name)
		if err != nil {
			return false, err
		}
		if len(cols) == 1 && cols[0] == "name" {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) indexColumns(ctx context.Context, indexName string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA index_info(`+quoteIdent(indexName)+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := []string{}
	for rows.Next() {
		var seqno int
		var cid int
		var name string
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func (s *Store) rebuildAPITokens(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE api_tokens_new (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			prefix TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			owner_user_id TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			last_used_at TEXT,
			expires_at TEXT,
			revoked_at TEXT
		)
	`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_tokens_new (
			id, name, token_hash, prefix, is_admin, owner_user_id, created_by,
			created_at, last_used_at, expires_at, revoked_at
		)
		SELECT
			id, name, token_hash, prefix, is_admin, owner_user_id, created_by,
			created_at, last_used_at, expires_at, revoked_at
		FROM api_tokens
	`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE api_tokens`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE api_tokens_new RENAME TO api_tokens`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) migrateLegacySSHKeys(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, managed_ssh_public_key, ssh_key_id, created_at FROM vms WHERE managed_ssh_public_key != ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type legacy struct {
		vmID, name, publicKey, sshKeyID, createdAt string
	}
	var legacyKeys []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.vmID, &l.name, &l.publicKey, &l.sshKeyID, &l.createdAt); err != nil {
			return err
		}
		legacyKeys = append(legacyKeys, l)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, l := range legacyKeys {
		if l.sshKeyID != "" {
			continue
		}
		normalized, fingerprint, keyType, err := sshkeys.NormalizePublicKey(l.publicKey)
		if err != nil {
			continue
		}
		keyID := "legacy-" + l.vmID
		keyName := l.name + "-legacy"
		if existing, err := s.GetSSHKeyByFingerprint(ctx, fingerprint); err != nil {
			return err
		} else if existing != nil {
			keyID = existing.ID
		} else {
			name := keyName
			for i := 2; ; i++ {
				_, err := s.db.ExecContext(ctx, `INSERT INTO ssh_keys (id, name, public_key, fingerprint, key_type, created_by, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
					keyID, name, normalized, fingerprint, keyType, "migration", defaultString(l.createdAt, now()))
				if err == nil {
					break
				}
				if !strings.Contains(err.Error(), "UNIQUE constraint failed: ssh_keys.name") {
					return err
				}
				keyID = "legacy-" + l.vmID + "-" + random.Hex(4)
				name = fmt.Sprintf("%s-%d", keyName, i)
			}
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE vms SET ssh_key_id = ?, managed_ssh_public_key = ? WHERE id = ?`, keyID, normalized, l.vmID); err != nil {
			return err
		}
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func parseNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t := parseTime(ns.String)
	return &t
}

func timePtrString(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (s *Store) HasUsers(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) CreateUser(ctx context.Context, u model.User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, boolInt(u.IsAdmin), u.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) UserByUsername(ctx context.Context, username string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func (s *Store) UserByID(ctx context.Context, id string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, is_admin, created_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, password_hash, is_admin, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*model.User, error) {
	var u model.User
	var admin int
	var created string
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &admin, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.IsAdmin = admin == 1
	u.CreatedAt = parseTime(created)
	return &u, nil
}

func (s *Store) CreateSession(ctx context.Context, sess model.Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id, user_id, csrf_token, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.CSRFToken, sess.CreatedAt.UTC().Format(time.RFC3339Nano), sess.LastSeenAt.UTC().Format(time.RFC3339Nano), sess.ExpiresAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SessionByID(ctx context.Context, id string) (*model.Session, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, csrf_token, created_at, last_seen_at, expires_at FROM sessions WHERE id = ?`, id)
	var sess model.Session
	var created, seen, expires string
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &created, &seen, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sess.CreatedAt = parseTime(created)
	sess.LastSeenAt = parseTime(seen)
	sess.ExpiresAt = parseTime(expires)
	return &sess, nil
}

func (s *Store) TouchSession(ctx context.Context, id string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`, now(), expires.UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *Store) CreateAPIToken(ctx context.Context, token model.APIToken, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens (id, name, token_hash, prefix, is_admin, owner_user_id, created_by, created_at, last_used_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.Name, tokenHash, token.Prefix, boolInt(token.IsAdmin), token.OwnerUserID, token.CreatedBy, token.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(token.LastUsedAt), timePtrString(token.ExpiresAt), timePtrString(token.RevokedAt))
	return err
}

func (s *Store) ListAPITokens(ctx context.Context) ([]model.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, apiTokenSelectSQL()+` ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanAPITokens(rows)
}

func (s *Store) ListAPITokensByOwner(ctx context.Context, ownerUserID string) ([]model.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, apiTokenSelectSQL()+` WHERE t.owner_user_id = ? ORDER BY t.created_at DESC`, ownerUserID)
	if err != nil {
		return nil, err
	}
	return scanAPITokens(rows)
}

func scanAPITokens(rows *sql.Rows) ([]model.APIToken, error) {
	defer rows.Close()
	out := []model.APIToken{}
	for rows.Next() {
		token, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *token)
	}
	return out, rows.Err()
}

func (s *Store) GetAPITokenByID(ctx context.Context, id string) (*model.APIToken, error) {
	row := s.db.QueryRowContext(ctx, apiTokenSelectSQL()+` WHERE t.id = ?`, id)
	return scanAPIToken(row)
}

func (s *Store) GetAPITokenByHash(ctx context.Context, tokenHash string) (*model.APIToken, error) {
	row := s.db.QueryRowContext(ctx, apiTokenSelectSQL()+` WHERE t.token_hash = ?`, tokenHash)
	return scanAPIToken(row)
}

func (s *Store) TouchAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now(), id)
	return err
}

func (s *Store) RevokeAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, now(), id)
	return err
}

func scanAPIToken(row rowScanner) (*model.APIToken, error) {
	var token model.APIToken
	var admin int
	var created string
	var lastUsed, expires, revoked sql.NullString
	if err := row.Scan(&token.ID, &token.Name, &token.Prefix, &admin, &token.OwnerUserID, &token.OwnerUsername, &token.CreatedBy, &created, &lastUsed, &expires, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	token.IsAdmin = admin == 1
	token.CreatedAt = parseTime(created)
	token.LastUsedAt = parseNullTime(lastUsed)
	token.ExpiresAt = parseNullTime(expires)
	token.RevokedAt = parseNullTime(revoked)
	return &token, nil
}

func apiTokenSelectSQL() string {
	return `SELECT t.id, t.name, t.prefix, t.is_admin, t.owner_user_id, COALESCE(u.username, ''), t.created_by, t.created_at, t.last_used_at, t.expires_at, t.revoked_at FROM api_tokens t LEFT JOIN users u ON u.id = t.owner_user_id`
}

func (s *Store) CreateSSHKey(ctx context.Context, key model.SSHKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ssh_keys (id, name, public_key, fingerprint, key_type, created_by, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.Name, key.PublicKey, key.Fingerprint, key.KeyType, key.CreatedBy, key.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(key.LastUsedAt))
	return err
}

func (s *Store) ListSSHKeys(ctx context.Context) ([]model.SSHKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, public_key, fingerprint, key_type, created_by, created_at, last_used_at FROM ssh_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SSHKey{}
	for rows.Next() {
		key, err := scanSSHKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *key)
	}
	return out, rows.Err()
}

func (s *Store) GetSSHKey(ctx context.Context, id string) (*model.SSHKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, public_key, fingerprint, key_type, created_by, created_at, last_used_at FROM ssh_keys WHERE id = ?`, id)
	return scanSSHKey(row)
}

func (s *Store) GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*model.SSHKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, public_key, fingerprint, key_type, created_by, created_at, last_used_at FROM ssh_keys WHERE fingerprint = ?`, fingerprint)
	return scanSSHKey(row)
}

func (s *Store) DeleteSSHKey(ctx context.Context, id string) error {
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vms WHERE ssh_key_id = ?`, id).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("SSH key is assigned to %d VM(s)", used)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id = ?`, id)
	return err
}

func (s *Store) TouchSSHKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE ssh_keys SET last_used_at = ? WHERE id = ?`, now(), id)
	return err
}

func scanSSHKey(row rowScanner) (*model.SSHKey, error) {
	var key model.SSHKey
	var created string
	var lastUsed sql.NullString
	if err := row.Scan(&key.ID, &key.Name, &key.PublicKey, &key.Fingerprint, &key.KeyType, &key.CreatedBy, &created, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	key.CreatedAt = parseTime(created)
	key.LastUsedAt = parseNullTime(lastUsed)
	return &key, nil
}

func (s *Store) ListVMs(ctx context.Context) ([]model.VM, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+vmColumns+` FROM vms ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.VM{}
	for rows.Next() {
		vm, err := scanVM(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *vm)
	}
	return out, rows.Err()
}

func (s *Store) GetVM(ctx context.Context, id string) (*model.VM, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+vmColumns+` FROM vms WHERE id = ?`, id)
	return scanVM(row)
}

func (s *Store) GetVMByName(ctx context.Context, name string) (*model.VM, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+vmColumns+` FROM vms WHERE name = ?`, name)
	return scanVM(row)
}

func (s *Store) CreateVM(ctx context.Context, vm model.VM) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vms (`+vmColumns+`) VALUES (`+vmPlaceholders+`)`, vmValues(vm)...)
	return err
}

func (s *Store) UpdateVM(ctx context.Context, vm model.VM) error {
	vm.UpdatedAt = time.Now().UTC()
	values := append(vmValues(vm), vm.ID)
	_, err := s.db.ExecContext(ctx, `UPDATE vms SET
		id=?, name=?, state=?, vcpu_count=?, mem_mib=?, ssh_port=?, tap_name=?, host_ip=?, guest_ip=?, cidr=?,
		kernel_path=?, kernel_id=?, rootfs_path=?, base_rootfs_path=?, base_image_id=?, rootfs_size_mib=?, dev_user=?, ssh_key_id=?, managed_ssh_public_key=?, managed_ssh_private_key_path=?,
		extra_authorized_keys=?, repo_url=?, git_ref=?, egress_mode=?, egress_policy_id=?, network_mode=?, network_id=?, last_error=?,
		created_at=?, updated_at=?, last_started_at=?, last_stopped_at=?
		WHERE id=?`, values...)
	return err
}

func (s *Store) DeleteVM(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ingress_rules WHERE vm_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vm_exec_jobs WHERE vm_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM vms WHERE id = ?`, id)
	return err
}

func (s *Store) UsedSSHPorts(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ssh_port FROM vms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, rows.Err()
}

func (s *Store) UsedIngressHostPorts(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_port FROM ingress_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, rows.Err()
}

func (s *Store) UsedGuestIPs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT guest_ip FROM vms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

func (s *Store) CreateNetwork(ctx context.Context, n model.Network) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO networks (id, name, cidr, gateway_ip, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		n.ID, n.Name, n.CIDR, n.GatewayIP, n.CreatedAt.UTC().Format(time.RFC3339Nano), n.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListNetworks(ctx context.Context) ([]model.Network, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, cidr, gateway_ip, created_at, updated_at FROM networks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Network{}
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (s *Store) GetNetwork(ctx context.Context, id string) (*model.Network, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, cidr, gateway_ip, created_at, updated_at FROM networks WHERE id = ?`, id)
	return scanNetwork(row)
}

func (s *Store) DeleteNetwork(ctx context.Context, id string) error {
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vms WHERE network_id = ?`, id).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("network is assigned to %d VM(s)", used)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM networks WHERE id = ?`, id)
	return err
}

func scanNetwork(row rowScanner) (*model.Network, error) {
	var n model.Network
	var created, updated string
	if err := row.Scan(&n.ID, &n.Name, &n.CIDR, &n.GatewayIP, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	n.CreatedAt = parseTime(created)
	n.UpdatedAt = parseTime(updated)
	return &n, nil
}

func (s *Store) CreateIngressRule(ctx context.Context, rule model.IngressRule) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ingress_rules (id, vm_id, protocol, host_port, guest_port, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.VMID, rule.Protocol, rule.HostPort, rule.GuestPort, rule.Description, rule.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListIngressRules(ctx context.Context, vmID string) ([]model.IngressRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, vm_id, protocol, host_port, guest_port, description, created_at FROM ingress_rules WHERE vm_id = ? ORDER BY host_port`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.IngressRule{}
	for rows.Next() {
		rule, err := scanIngressRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rule)
	}
	return out, rows.Err()
}

func (s *Store) DeleteIngressRule(ctx context.Context, vmID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ingress_rules WHERE vm_id = ? AND id = ?`, vmID, id)
	return err
}

func scanIngressRule(row rowScanner) (*model.IngressRule, error) {
	var rule model.IngressRule
	var created string
	if err := row.Scan(&rule.ID, &rule.VMID, &rule.Protocol, &rule.HostPort, &rule.GuestPort, &rule.Description, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rule.CreatedAt = parseTime(created)
	return &rule, nil
}

func (s *Store) CreateEgressPolicy(ctx context.Context, policy model.EgressPolicy) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO egress_policies (id, name, mode, tcp_ports, udp_ports, cidrs, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		policy.ID, policy.Name, policy.Mode, policy.TCPPorts, policy.UDPPorts, policy.CIDRs, policy.CreatedAt.UTC().Format(time.RFC3339Nano), policy.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListEgressPolicies(ctx context.Context) ([]model.EgressPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, mode, tcp_ports, udp_ports, cidrs, created_at, updated_at FROM egress_policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.EgressPolicy{}
	for rows.Next() {
		policy, err := scanEgressPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *policy)
	}
	return out, rows.Err()
}

func (s *Store) GetEgressPolicy(ctx context.Context, id string) (*model.EgressPolicy, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, mode, tcp_ports, udp_ports, cidrs, created_at, updated_at FROM egress_policies WHERE id = ?`, id)
	return scanEgressPolicy(row)
}

func (s *Store) DeleteEgressPolicy(ctx context.Context, id string) error {
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vms WHERE egress_policy_id = ?`, id).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("egress policy is assigned to %d VM(s)", used)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM egress_policies WHERE id = ?`, id)
	return err
}

func scanEgressPolicy(row rowScanner) (*model.EgressPolicy, error) {
	var policy model.EgressPolicy
	var created, updated string
	if err := row.Scan(&policy.ID, &policy.Name, &policy.Mode, &policy.TCPPorts, &policy.UDPPorts, &policy.CIDRs, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	policy.CreatedAt = parseTime(created)
	policy.UpdatedAt = parseTime(updated)
	return &policy, nil
}

func (s *Store) CreateBaseImage(ctx context.Context, image model.BaseImage) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO base_images (id, name, status, filesystem, path, virtual_size_mib, disk_size_bytes, checksum, packages, hooks, provenance, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		image.ID, image.Name, image.Status, image.Filesystem, image.Path, image.VirtualSizeMiB, image.DiskSizeBytes, image.Checksum, image.Packages, image.Hooks, image.Provenance, image.CreatedBy, image.CreatedAt.UTC().Format(time.RFC3339Nano), image.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListBaseImages(ctx context.Context) ([]model.BaseImage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, status, filesystem, path, virtual_size_mib, disk_size_bytes, checksum, packages, hooks, provenance, created_by, created_at, updated_at FROM base_images ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BaseImage{}
	for rows.Next() {
		image, err := scanBaseImage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *image)
	}
	return out, rows.Err()
}

func (s *Store) GetBaseImage(ctx context.Context, id string) (*model.BaseImage, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, status, filesystem, path, virtual_size_mib, disk_size_bytes, checksum, packages, hooks, provenance, created_by, created_at, updated_at FROM base_images WHERE id = ?`, id)
	return scanBaseImage(row)
}

func (s *Store) GetBaseImageByPath(ctx context.Context, path string) (*model.BaseImage, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, status, filesystem, path, virtual_size_mib, disk_size_bytes, checksum, packages, hooks, provenance, created_by, created_at, updated_at FROM base_images WHERE path = ?`, path)
	return scanBaseImage(row)
}

func (s *Store) DefaultBaseImage(ctx context.Context) (*model.BaseImage, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, status, filesystem, path, virtual_size_mib, disk_size_bytes, checksum, packages, hooks, provenance, created_by, created_at, updated_at FROM base_images WHERE status = 'active' ORDER BY created_at ASC LIMIT 1`)
	return scanBaseImage(row)
}

func (s *Store) UpdateBaseImage(ctx context.Context, image model.BaseImage) error {
	image.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE base_images SET name=?, status=?, filesystem=?, path=?, virtual_size_mib=?, disk_size_bytes=?, checksum=?, packages=?, hooks=?, provenance=?, created_by=?, created_at=?, updated_at=? WHERE id=?`,
		image.Name, image.Status, image.Filesystem, image.Path, image.VirtualSizeMiB, image.DiskSizeBytes, image.Checksum, image.Packages, image.Hooks, image.Provenance, image.CreatedBy, image.CreatedAt.UTC().Format(time.RFC3339Nano), image.UpdatedAt.UTC().Format(time.RFC3339Nano), image.ID)
	return err
}

func (s *Store) DeleteBaseImage(ctx context.Context, id string) error {
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vms WHERE base_image_id = ?`, id).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("base image is assigned to %d VM(s)", used)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM base_images WHERE id = ?`, id)
	return err
}

func scanBaseImage(row rowScanner) (*model.BaseImage, error) {
	var image model.BaseImage
	var created, updated string
	if err := row.Scan(&image.ID, &image.Name, &image.Status, &image.Filesystem, &image.Path, &image.VirtualSizeMiB, &image.DiskSizeBytes, &image.Checksum, &image.Packages, &image.Hooks, &image.Provenance, &image.CreatedBy, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	image.CreatedAt = parseTime(created)
	image.UpdatedAt = parseTime(updated)
	return &image, nil
}

func (s *Store) CreateImageBuildJob(ctx context.Context, job model.ImageBuildJob) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO image_build_jobs (id, status, name, filesystem, size_mib, packages, hooks, log_path, result_image_id, error, created_by, created_at, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.Status, job.Name, job.Filesystem, job.SizeMiB, job.Packages, job.Hooks, job.LogPath, job.ResultImageID, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt))
	return err
}

func (s *Store) UpdateImageBuildJob(ctx context.Context, job model.ImageBuildJob) error {
	_, err := s.db.ExecContext(ctx, `UPDATE image_build_jobs SET status=?, name=?, filesystem=?, size_mib=?, packages=?, hooks=?, log_path=?, result_image_id=?, error=?, created_by=?, created_at=?, started_at=?, completed_at=? WHERE id=?`,
		job.Status, job.Name, job.Filesystem, job.SizeMiB, job.Packages, job.Hooks, job.LogPath, job.ResultImageID, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt), job.ID)
	return err
}

func (s *Store) ListImageBuildJobs(ctx context.Context) ([]model.ImageBuildJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, status, name, filesystem, size_mib, packages, hooks, log_path, result_image_id, error, created_by, created_at, started_at, completed_at FROM image_build_jobs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ImageBuildJob{}
	for rows.Next() {
		job, err := scanImageBuildJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *job)
	}
	return out, rows.Err()
}

func (s *Store) GetImageBuildJob(ctx context.Context, id string) (*model.ImageBuildJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, status, name, filesystem, size_mib, packages, hooks, log_path, result_image_id, error, created_by, created_at, started_at, completed_at FROM image_build_jobs WHERE id = ?`, id)
	return scanImageBuildJob(row)
}

func scanImageBuildJob(row rowScanner) (*model.ImageBuildJob, error) {
	var job model.ImageBuildJob
	var created string
	var started, completed sql.NullString
	if err := row.Scan(&job.ID, &job.Status, &job.Name, &job.Filesystem, &job.SizeMiB, &job.Packages, &job.Hooks, &job.LogPath, &job.ResultImageID, &job.Error, &job.CreatedBy, &created, &started, &completed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	job.CreatedAt = parseTime(created)
	job.StartedAt = parseNullTime(started)
	job.CompletedAt = parseNullTime(completed)
	return &job, nil
}

func (s *Store) CreateImageHook(ctx context.Context, hook model.ImageHook) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO image_hooks (id, name, source_type, status, content_path, git_url, git_ref, git_path, resolved_commit, checksum, created_by, created_at, updated_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hook.ID, hook.Name, hook.SourceType, hook.Status, hook.ContentPath, hook.GitURL, hook.GitRef, hook.GitPath, hook.ResolvedCommit, hook.Checksum, hook.CreatedBy, hook.CreatedAt.UTC().Format(time.RFC3339Nano), hook.UpdatedAt.UTC().Format(time.RFC3339Nano), timePtrString(hook.LastUsedAt))
	return err
}

func (s *Store) UpdateImageHook(ctx context.Context, hook model.ImageHook) error {
	hook.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE image_hooks SET name=?, source_type=?, status=?, content_path=?, git_url=?, git_ref=?, git_path=?, resolved_commit=?, checksum=?, created_by=?, created_at=?, updated_at=?, last_used_at=? WHERE id=?`,
		hook.Name, hook.SourceType, hook.Status, hook.ContentPath, hook.GitURL, hook.GitRef, hook.GitPath, hook.ResolvedCommit, hook.Checksum, hook.CreatedBy, hook.CreatedAt.UTC().Format(time.RFC3339Nano), hook.UpdatedAt.UTC().Format(time.RFC3339Nano), timePtrString(hook.LastUsedAt), hook.ID)
	return err
}

func (s *Store) ListImageHooks(ctx context.Context) ([]model.ImageHook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, source_type, status, content_path, git_url, git_ref, git_path, resolved_commit, checksum, created_by, created_at, updated_at, last_used_at FROM image_hooks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ImageHook{}
	for rows.Next() {
		hook, err := scanImageHook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *hook)
	}
	return out, rows.Err()
}

func (s *Store) GetImageHook(ctx context.Context, id string) (*model.ImageHook, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, source_type, status, content_path, git_url, git_ref, git_path, resolved_commit, checksum, created_by, created_at, updated_at, last_used_at FROM image_hooks WHERE id = ?`, id)
	return scanImageHook(row)
}

func (s *Store) DeleteImageHook(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM image_hooks WHERE id = ?`, id)
	return err
}

func scanImageHook(row rowScanner) (*model.ImageHook, error) {
	var hook model.ImageHook
	var created, updated string
	var lastUsed sql.NullString
	if err := row.Scan(&hook.ID, &hook.Name, &hook.SourceType, &hook.Status, &hook.ContentPath, &hook.GitURL, &hook.GitRef, &hook.GitPath, &hook.ResolvedCommit, &hook.Checksum, &hook.CreatedBy, &created, &updated, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	hook.CreatedAt = parseTime(created)
	hook.UpdatedAt = parseTime(updated)
	hook.LastUsedAt = parseNullTime(lastUsed)
	return &hook, nil
}

func (s *Store) CreateKernel(ctx context.Context, kernel model.Kernel) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO kernels (id, name, version, architecture, status, source_type, path, config_path, checksum, boot_args, provenance, created_by, created_at, updated_at, last_tested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		kernel.ID, kernel.Name, kernel.Version, kernel.Architecture, kernel.Status, kernel.SourceType, kernel.Path, kernel.ConfigPath, kernel.Checksum, kernel.BootArgs, kernel.Provenance, kernel.CreatedBy, kernel.CreatedAt.UTC().Format(time.RFC3339Nano), kernel.UpdatedAt.UTC().Format(time.RFC3339Nano), timePtrString(kernel.LastTestedAt))
	return err
}

func (s *Store) ListKernels(ctx context.Context) ([]model.Kernel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, version, architecture, status, source_type, path, config_path, checksum, boot_args, provenance, created_by, created_at, updated_at, last_tested_at FROM kernels ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Kernel{}
	for rows.Next() {
		kernel, err := scanKernel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *kernel)
	}
	return out, rows.Err()
}

func (s *Store) GetKernel(ctx context.Context, id string) (*model.Kernel, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, version, architecture, status, source_type, path, config_path, checksum, boot_args, provenance, created_by, created_at, updated_at, last_tested_at FROM kernels WHERE id = ?`, id)
	return scanKernel(row)
}

func (s *Store) GetKernelByPath(ctx context.Context, path string) (*model.Kernel, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, version, architecture, status, source_type, path, config_path, checksum, boot_args, provenance, created_by, created_at, updated_at, last_tested_at FROM kernels WHERE path = ?`, path)
	return scanKernel(row)
}

func (s *Store) DefaultKernel(ctx context.Context) (*model.Kernel, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, version, architecture, status, source_type, path, config_path, checksum, boot_args, provenance, created_by, created_at, updated_at, last_tested_at FROM kernels WHERE status = 'active' ORDER BY created_at ASC LIMIT 1`)
	return scanKernel(row)
}

func (s *Store) UpdateKernel(ctx context.Context, kernel model.Kernel) error {
	kernel.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE kernels SET name=?, version=?, architecture=?, status=?, source_type=?, path=?, config_path=?, checksum=?, boot_args=?, provenance=?, created_by=?, created_at=?, updated_at=?, last_tested_at=? WHERE id=?`,
		kernel.Name, kernel.Version, kernel.Architecture, kernel.Status, kernel.SourceType, kernel.Path, kernel.ConfigPath, kernel.Checksum, kernel.BootArgs, kernel.Provenance, kernel.CreatedBy, kernel.CreatedAt.UTC().Format(time.RFC3339Nano), kernel.UpdatedAt.UTC().Format(time.RFC3339Nano), timePtrString(kernel.LastTestedAt), kernel.ID)
	return err
}

func (s *Store) BackfillVMKernelID(ctx context.Context, kernelID, kernelPath string) error {
	if kernelID == "" || kernelPath == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE vms SET kernel_id = ? WHERE kernel_id = '' AND kernel_path = ?`, kernelID, kernelPath)
	return err
}

func (s *Store) DeleteKernel(ctx context.Context, id string) error {
	var path string
	if err := s.db.QueryRowContext(ctx, `SELECT path FROM kernels WHERE id = ?`, id).Scan(&path); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vms WHERE kernel_id = ? OR kernel_path = ?`, id, path).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("kernel is assigned to %d VM(s)", used)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM kernel_test_jobs WHERE kernel_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM kernels WHERE id = ?`, id)
	return err
}

func scanKernel(row rowScanner) (*model.Kernel, error) {
	var kernel model.Kernel
	var created, updated string
	var lastTested sql.NullString
	if err := row.Scan(&kernel.ID, &kernel.Name, &kernel.Version, &kernel.Architecture, &kernel.Status, &kernel.SourceType, &kernel.Path, &kernel.ConfigPath, &kernel.Checksum, &kernel.BootArgs, &kernel.Provenance, &kernel.CreatedBy, &created, &updated, &lastTested); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	kernel.CreatedAt = parseTime(created)
	kernel.UpdatedAt = parseTime(updated)
	kernel.LastTestedAt = parseNullTime(lastTested)
	return &kernel, nil
}

func (s *Store) CreateKernelTestJob(ctx context.Context, job model.KernelTestJob) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO kernel_test_jobs (id, kernel_id, status, log_path, base_image_id, uname_result, error, created_by, created_at, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.KernelID, job.Status, job.LogPath, job.BaseImageID, job.UnameResult, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt))
	return err
}

func (s *Store) UpdateKernelTestJob(ctx context.Context, job model.KernelTestJob) error {
	_, err := s.db.ExecContext(ctx, `UPDATE kernel_test_jobs SET kernel_id=?, status=?, log_path=?, base_image_id=?, uname_result=?, error=?, created_by=?, created_at=?, started_at=?, completed_at=? WHERE id=?`,
		job.KernelID, job.Status, job.LogPath, job.BaseImageID, job.UnameResult, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt), job.ID)
	return err
}

func (s *Store) ListKernelTestJobs(ctx context.Context) ([]model.KernelTestJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kernel_id, status, log_path, base_image_id, uname_result, error, created_by, created_at, started_at, completed_at FROM kernel_test_jobs ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.KernelTestJob{}
	for rows.Next() {
		job, err := scanKernelTestJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *job)
	}
	return out, rows.Err()
}

func (s *Store) GetKernelTestJob(ctx context.Context, id string) (*model.KernelTestJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, kernel_id, status, log_path, base_image_id, uname_result, error, created_by, created_at, started_at, completed_at FROM kernel_test_jobs WHERE id = ?`, id)
	return scanKernelTestJob(row)
}

func scanKernelTestJob(row rowScanner) (*model.KernelTestJob, error) {
	var job model.KernelTestJob
	var created string
	var started, completed sql.NullString
	if err := row.Scan(&job.ID, &job.KernelID, &job.Status, &job.LogPath, &job.BaseImageID, &job.UnameResult, &job.Error, &job.CreatedBy, &created, &started, &completed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	job.CreatedAt = parseTime(created)
	job.StartedAt = parseNullTime(started)
	job.CompletedAt = parseNullTime(completed)
	return &job, nil
}

func (s *Store) CreateKernelDiscoveryJob(ctx context.Context, job model.KernelDiscoveryJob) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO kernel_discovery_jobs (id, status, source_url, ci_prefix, architecture, item_count, error, created_by, created_at, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.Status, job.SourceURL, job.CIPrefix, job.Architecture, job.ItemCount, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt))
	return err
}

func (s *Store) UpdateKernelDiscoveryJob(ctx context.Context, job model.KernelDiscoveryJob) error {
	_, err := s.db.ExecContext(ctx, `UPDATE kernel_discovery_jobs SET status=?, source_url=?, ci_prefix=?, architecture=?, item_count=?, error=?, created_by=?, created_at=?, started_at=?, completed_at=? WHERE id=?`,
		job.Status, job.SourceURL, job.CIPrefix, job.Architecture, job.ItemCount, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt), job.ID)
	return err
}

func (s *Store) ListKernelDiscoveryJobs(ctx context.Context) ([]model.KernelDiscoveryJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, status, source_url, ci_prefix, architecture, item_count, error, created_by, created_at, started_at, completed_at FROM kernel_discovery_jobs ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.KernelDiscoveryJob{}
	for rows.Next() {
		job, err := scanKernelDiscoveryJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *job)
	}
	return out, rows.Err()
}

func (s *Store) LatestKernelDiscoveryJob(ctx context.Context) (*model.KernelDiscoveryJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, status, source_url, ci_prefix, architecture, item_count, error, created_by, created_at, started_at, completed_at FROM kernel_discovery_jobs ORDER BY created_at DESC LIMIT 1`)
	return scanKernelDiscoveryJob(row)
}

func (s *Store) GetKernelDiscoveryJob(ctx context.Context, id string) (*model.KernelDiscoveryJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, status, source_url, ci_prefix, architecture, item_count, error, created_by, created_at, started_at, completed_at FROM kernel_discovery_jobs WHERE id = ?`, id)
	return scanKernelDiscoveryJob(row)
}

func scanKernelDiscoveryJob(row rowScanner) (*model.KernelDiscoveryJob, error) {
	var job model.KernelDiscoveryJob
	var created string
	var started, completed sql.NullString
	if err := row.Scan(&job.ID, &job.Status, &job.SourceURL, &job.CIPrefix, &job.Architecture, &job.ItemCount, &job.Error, &job.CreatedBy, &created, &started, &completed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	job.CreatedAt = parseTime(created)
	job.StartedAt = parseNullTime(started)
	job.CompletedAt = parseNullTime(completed)
	return &job, nil
}

func (s *Store) ReplaceKernelDiscoveryItems(ctx context.Context, jobID string, items []model.KernelDiscoveryItem) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM kernel_discovery_items WHERE job_id = ?`, jobID); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO kernel_discovery_items (id, job_id, version, variant, architecture, ci_prefix, kernel_key, config_key, kernel_url, config_url, already_registered, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, item := range items {
		if _, err := stmt.ExecContext(ctx, item.ID, item.JobID, item.Version, item.Variant, item.Architecture, item.CIPrefix, item.KernelKey, item.ConfigKey, item.KernelURL, item.ConfigURL, boolInt(item.AlreadyRegistered), item.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListKernelDiscoveryItems(ctx context.Context, jobID string) ([]model.KernelDiscoveryItem, error) {
	query := `SELECT id, job_id, version, variant, architecture, ci_prefix, kernel_key, config_key, kernel_url, config_url, already_registered, created_at FROM kernel_discovery_items`
	args := []any{}
	if jobID != "" {
		query += ` WHERE job_id = ?`
		args = append(args, jobID)
	}
	query += ` ORDER BY created_at DESC, version DESC, variant ASC LIMIT 200`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.KernelDiscoveryItem{}
	for rows.Next() {
		item, err := scanKernelDiscoveryItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *item)
	}
	return out, rows.Err()
}

func (s *Store) GetKernelDiscoveryItem(ctx context.Context, id string) (*model.KernelDiscoveryItem, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, job_id, version, variant, architecture, ci_prefix, kernel_key, config_key, kernel_url, config_url, already_registered, created_at FROM kernel_discovery_items WHERE id = ?`, id)
	return scanKernelDiscoveryItem(row)
}

func (s *Store) MarkKernelDiscoveryItemRegistered(ctx context.Context, id string, registered bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE kernel_discovery_items SET already_registered = ? WHERE id = ?`, boolInt(registered), id)
	return err
}

func scanKernelDiscoveryItem(row rowScanner) (*model.KernelDiscoveryItem, error) {
	var item model.KernelDiscoveryItem
	var registered int
	var created string
	if err := row.Scan(&item.ID, &item.JobID, &item.Version, &item.Variant, &item.Architecture, &item.CIPrefix, &item.KernelKey, &item.ConfigKey, &item.KernelURL, &item.ConfigURL, &registered, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	item.AlreadyRegistered = registered != 0
	item.CreatedAt = parseTime(created)
	return &item, nil
}

func (s *Store) CreateVMExecJob(ctx context.Context, job model.VMExecJob) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vm_exec_jobs (id, vm_id, status, command, cwd, env_json, pty, timeout_seconds, stdout, stderr, exit_code, timed_out, truncated, log_path, error, created_by, created_at, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.VMID, job.Status, job.Command, job.CWD, job.EnvJSON, boolInt(job.PTY), job.TimeoutSeconds, job.Stdout, job.Stderr, job.ExitCode, boolInt(job.TimedOut), boolInt(job.Truncated), job.LogPath, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt))
	return err
}

func (s *Store) UpdateVMExecJob(ctx context.Context, job model.VMExecJob) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vm_exec_jobs SET vm_id=?, status=?, command=?, cwd=?, env_json=?, pty=?, timeout_seconds=?, stdout=?, stderr=?, exit_code=?, timed_out=?, truncated=?, log_path=?, error=?, created_by=?, created_at=?, started_at=?, completed_at=? WHERE id=?`,
		job.VMID, job.Status, job.Command, job.CWD, job.EnvJSON, boolInt(job.PTY), job.TimeoutSeconds, job.Stdout, job.Stderr, job.ExitCode, boolInt(job.TimedOut), boolInt(job.Truncated), job.LogPath, job.Error, job.CreatedBy, job.CreatedAt.UTC().Format(time.RFC3339Nano), timePtrString(job.StartedAt), timePtrString(job.CompletedAt), job.ID)
	return err
}

func (s *Store) ListVMExecJobs(ctx context.Context, vmID string) ([]model.VMExecJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, vm_id, status, command, cwd, env_json, pty, timeout_seconds, stdout, stderr, exit_code, timed_out, truncated, log_path, error, created_by, created_at, started_at, completed_at FROM vm_exec_jobs WHERE vm_id = ? ORDER BY created_at DESC LIMIT 50`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.VMExecJob{}
	for rows.Next() {
		job, err := scanVMExecJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *job)
	}
	return out, rows.Err()
}

func (s *Store) GetVMExecJob(ctx context.Context, vmID, id string) (*model.VMExecJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, vm_id, status, command, cwd, env_json, pty, timeout_seconds, stdout, stderr, exit_code, timed_out, truncated, log_path, error, created_by, created_at, started_at, completed_at FROM vm_exec_jobs WHERE vm_id = ? AND id = ?`, vmID, id)
	return scanVMExecJob(row)
}

func scanVMExecJob(row rowScanner) (*model.VMExecJob, error) {
	var job model.VMExecJob
	var pty, timedOut, truncated int
	var created string
	var started, completed sql.NullString
	if err := row.Scan(&job.ID, &job.VMID, &job.Status, &job.Command, &job.CWD, &job.EnvJSON, &pty, &job.TimeoutSeconds, &job.Stdout, &job.Stderr, &job.ExitCode, &timedOut, &truncated, &job.LogPath, &job.Error, &job.CreatedBy, &created, &started, &completed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	job.PTY = pty != 0
	job.TimedOut = timedOut != 0
	job.Truncated = truncated != 0
	job.CreatedAt = parseTime(created)
	job.StartedAt = parseNullTime(started)
	job.CompletedAt = parseNullTime(completed)
	return &job, nil
}

func (s *Store) Audit(ctx context.Context, actor, source, action, target, outcome, requestID, message string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events (actor, source, action, target, outcome, request_id, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		actor, source, action, target, outcome, requestID, message, now())
	return err
}

const vmColumns = `id, name, state, vcpu_count, mem_mib, ssh_port, tap_name, host_ip, guest_ip, cidr,
kernel_path, kernel_id, rootfs_path, base_rootfs_path, base_image_id, rootfs_size_mib, dev_user, ssh_key_id, managed_ssh_public_key, managed_ssh_private_key_path,
extra_authorized_keys, repo_url, git_ref, egress_mode, egress_policy_id, network_mode, network_id, last_error,
created_at, updated_at, last_started_at, last_stopped_at`

const vmPlaceholders = `?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`

func vmValues(vm model.VM) []any {
	return []any{
		vm.ID, vm.Name, string(vm.State), vm.VCPUCount, vm.MemMiB, vm.SSHPort, vm.TapName, vm.HostIP, vm.GuestIP, vm.CIDR,
		vm.KernelPath, vm.KernelID, vm.RootFSPath, vm.BaseRootFSPath, vm.BaseImageID, vm.RootFSSizeMiB, vm.DevUser, vm.SSHKeyID, vm.ManagedSSHPublicKey, vm.ManagedSSHPrivateKeyPath,
		vm.ExtraAuthorizedKeys, vm.RepoURL, vm.GitRef, vm.EgressMode, vm.EgressPolicyID, vm.NetworkMode, vm.NetworkID, vm.LastError,
		vm.CreatedAt.UTC().Format(time.RFC3339Nano), vm.UpdatedAt.UTC().Format(time.RFC3339Nano), timePtrString(vm.LastStartedAt), timePtrString(vm.LastStoppedAt),
	}
}

func scanVM(row rowScanner) (*model.VM, error) {
	var vm model.VM
	var state string
	var created, updated string
	var started, stopped sql.NullString
	err := row.Scan(
		&vm.ID, &vm.Name, &state, &vm.VCPUCount, &vm.MemMiB, &vm.SSHPort, &vm.TapName, &vm.HostIP, &vm.GuestIP, &vm.CIDR,
		&vm.KernelPath, &vm.KernelID, &vm.RootFSPath, &vm.BaseRootFSPath, &vm.BaseImageID, &vm.RootFSSizeMiB, &vm.DevUser, &vm.SSHKeyID, &vm.ManagedSSHPublicKey, &vm.ManagedSSHPrivateKeyPath,
		&vm.ExtraAuthorizedKeys, &vm.RepoURL, &vm.GitRef, &vm.EgressMode, &vm.EgressPolicyID, &vm.NetworkMode, &vm.NetworkID, &vm.LastError,
		&created, &updated, &started, &stopped,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	vm.State = model.VMState(state)
	vm.CreatedAt = parseTime(created)
	vm.UpdatedAt = parseTime(updated)
	vm.LastStartedAt = parseNullTime(started)
	vm.LastStoppedAt = parseNullTime(stopped)
	return &vm, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func defaultString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
