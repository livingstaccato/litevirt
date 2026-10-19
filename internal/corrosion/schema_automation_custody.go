package corrosion

import (
	"context"
	"fmt"
	"strings"
)

const automationCustodyMigrationID = "r_automation_key_recipients_host_zero"
const automationCustodyRecipientTable = "local_automation_key_recipients"
const automationCustodyReplacementTable = "local_automation_key_recipients__schema81"
const automationCustodyRecipientColumns = "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence"
const automationCustodyRecipientBody = ` (
 stage TEXT NOT NULL, cluster_uid TEXT NOT NULL, recipient_epoch TEXT NOT NULL,
 membership_generation INTEGER NOT NULL CHECK(membership_generation>0), config_digest TEXT NOT NULL,
 host TEXT NOT NULL, host_incarnation INTEGER NOT NULL CHECK(host_incarnation>=0), admitted_at TEXT NOT NULL,
 admission_serial TEXT NOT NULL, voter_incarnation TEXT NOT NULL, key_id TEXT NOT NULL, recipient TEXT NOT NULL,
 enrollment_ref TEXT NOT NULL, recipient_ack_ref TEXT NOT NULL, equality_ack_ref TEXT NOT NULL,
 first_sequence INTEGER NOT NULL CHECK(first_sequence>0), PRIMARY KEY(stage,cluster_uid,recipient_epoch,host))`
const automationCustodyRecipientDDL = "CREATE TABLE IF NOT EXISTS " + automationCustodyRecipientTable + automationCustodyRecipientBody
const automationCustodyCreateReplacement = "CREATE TABLE " + automationCustodyReplacementTable + automationCustodyRecipientBody
const automationCustodyCopyRecipients = "INSERT INTO " + automationCustodyReplacementTable + "(" + automationCustodyRecipientColumns + ") SELECT " + automationCustodyRecipientColumns + " FROM " + automationCustodyRecipientTable
const automationCustodyDropOriginal = "DROP TABLE " + automationCustodyRecipientTable
const automationCustodyRenameReplacement = "ALTER TABLE " + automationCustodyReplacementTable + " RENAME TO " + automationCustodyRecipientTable
const automationCustodyKeyIDIndex = "CREATE UNIQUE INDEX automation_key_id ON local_automation_key_recipients(stage,cluster_uid,key_id)"
const automationCustodyRecipientIndex = "CREATE UNIQUE INDEX automation_key_recipient ON local_automation_key_recipients(stage,cluster_uid,recipient)"

// This identity covers exactly the statements used by the new unit. No earlier
// migration's ID/order/SQL/checksum changes; its original create-table SQL is empty.
const automationCustodyRebuildSQL = automationCustodyCreateReplacement + ";\n" + automationCustodyCopyRecipients + ";\n" + automationCustodyDropOriginal + ";\n" + automationCustodyRenameReplacement + ";\n" + automationCustodyKeyIDIndex + ";\n" + automationCustodyRecipientIndex

func preflightAutomationCustodySchema(ctx context.Context, c *Client) error {
	occupied, err := c.Query(ctx, `SELECT name FROM sqlite_master WHERE name=? COLLATE NOCASE`, automationCustodyReplacementTable)
	if err != nil {
		return err
	}
	if len(occupied) != 0 {
		return fmt.Errorf("custody replacement name is occupied")
	}
	exists, err := tableExists(ctx, c, automationCustodyRecipientTable)
	if err != nil || !exists {
		return err
	}
	_, err = automationCustodyRecipientShape(ctx, c)
	return err
}

// Only the frozen original >0 and corrected >=0 table definitions are supported.
// Insignificant SQL whitespace/case and SQLite's rename quoting of the table
// name are accepted; arbitrary constraints, columns or alternate keys are not.
func automationCustodySQLShape(raw string) string {
	s := strings.Join(strings.Fields(strings.ToLower(raw)), "")
	s = strings.Replace(s, "createtableifnotexists", "createtable", 1)
	return strings.Replace(s, `createtable"local_automation_key_recipients"(`, "createtablelocal_automation_key_recipients(", 1)
}

func automationCustodyRecipientShape(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, automationCustodyRecipientTable)
	if err != nil {
		return false, err
	}
	if len(rows) != 1 {
		return false, fmt.Errorf("custody recipient table missing")
	}
	shape := automationCustodySQLShape(rows[0].String("sql"))
	corrected := automationCustodySQLShape(automationCustodyRecipientDDL)
	original := strings.Replace(corrected, "check(host_incarnation>=0)", "check(host_incarnation>0)", 1)
	if shape != original && shape != corrected {
		return false, fmt.Errorf("unsupported custody recipient CREATE shape")
	}
	info, err := c.Query(ctx, `PRAGMA table_xinfo(local_automation_key_recipients)`)
	if err != nil {
		return false, err
	}
	columns := strings.Split(automationCustodyRecipientColumns, ",")
	if len(info) != len(columns) {
		return false, fmt.Errorf("unsupported custody recipient column count")
	}
	pk := map[string]int64{"stage": 1, "cluster_uid": 2, "recipient_epoch": 3, "host": 4}
	for i, row := range info {
		typ := "TEXT"
		if columns[i] == "membership_generation" || columns[i] == "host_incarnation" || columns[i] == "first_sequence" {
			typ = "INTEGER"
		}
		if row.Int64("cid") != int64(i) || row.String("name") != columns[i] || row.String("type") != typ || row.Int64("notnull") != 1 || row.get("dflt_value") != nil || row.Int64("hidden") != 0 || row.Int64("pk") != pk[columns[i]] {
			return false, fmt.Errorf("unsupported custody recipient column %s", columns[i])
		}
	}
	triggers, err := c.Query(ctx, `SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?`, automationCustodyRecipientTable)
	if err != nil {
		return false, err
	}
	if len(triggers) != 0 {
		return false, fmt.Errorf("unsupported custody recipient triggers")
	}
	indexes, err := c.Query(ctx, `PRAGMA index_list(local_automation_key_recipients)`)
	if err != nil {
		return false, err
	}
	if len(indexes) != 3 {
		return false, fmt.Errorf("unsupported custody recipient index count")
	}
	want := map[string]string{"sqlite_autoindex_local_automation_key_recipients_1": "stage,cluster_uid,recipient_epoch,host", "automation_key_id": "stage,cluster_uid,key_id", "automation_key_recipient": "stage,cluster_uid,recipient"}
	for _, index := range indexes {
		name := index.String("name")
		key, ok := want[name]
		origin := "c"
		if strings.HasPrefix(name, "sqlite_autoindex_") {
			origin = "pk"
		}
		if !ok || index.Int64("unique") != 1 || index.Int64("partial") != 0 || index.String("origin") != origin {
			return false, fmt.Errorf("unsupported custody recipient index %s", name)
		}
		keys, err := c.Query(ctx, `SELECT seqno,name,coll,"desc" FROM pragma_index_xinfo(?) WHERE "key"=1 ORDER BY seqno`, name)
		if err != nil {
			return false, err
		}
		parts := strings.Split(key, ",")
		if len(keys) != len(parts) {
			return false, fmt.Errorf("unsupported custody recipient index keys")
		}
		for i, column := range keys {
			if column.Int64("seqno") != int64(i) || column.String("name") != parts[i] || column.String("coll") != "BINARY" || column.Int64("desc") != 0 {
				return false, fmt.Errorf("unsupported custody recipient index order")
			}
		}
	}
	return shape == corrected, nil
}

func rebuildAutomationCustodyStatements(ctx context.Context, c *Client) ([]Statement, error) {
	if err := preflightAutomationCustodySchema(ctx, c); err != nil {
		return nil, err
	}
	corrected, err := automationCustodyRecipientShape(ctx, c)
	if err != nil {
		return nil, err
	}
	if corrected {
		return nil, fmt.Errorf("custody recipient rebuild requested for corrected table")
	}
	// Plain all-column/all-stage copy; CHECK/copy/rename/index/ledger failures
	// roll back together in the caller's single execBatchLocal transaction.
	return []Statement{
		{SQL: automationCustodyCreateReplacement},
		{SQL: automationCustodyCopyRecipients},
		{SQL: automationCustodyDropOriginal},
		{SQL: automationCustodyRenameReplacement},
		{SQL: automationCustodyKeyIDIndex},
		{SQL: automationCustodyRecipientIndex},
	}, nil
}
