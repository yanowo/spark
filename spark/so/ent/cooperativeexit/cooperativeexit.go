// Code generated by ent, DO NOT EDIT.

package cooperativeexit

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the cooperativeexit type in the database.
	Label = "cooperative_exit"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCreateTime holds the string denoting the create_time field in the database.
	FieldCreateTime = "create_time"
	// FieldUpdateTime holds the string denoting the update_time field in the database.
	FieldUpdateTime = "update_time"
	// FieldExitTxid holds the string denoting the exit_txid field in the database.
	FieldExitTxid = "exit_txid"
	// FieldConfirmationHeight holds the string denoting the confirmation_height field in the database.
	FieldConfirmationHeight = "confirmation_height"
	// EdgeTransfer holds the string denoting the transfer edge name in mutations.
	EdgeTransfer = "transfer"
	// Table holds the table name of the cooperativeexit in the database.
	Table = "cooperative_exits"
	// TransferTable is the table that holds the transfer relation/edge.
	TransferTable = "cooperative_exits"
	// TransferInverseTable is the table name for the Transfer entity.
	// It exists in this package in order to avoid circular dependency with the "transfer" package.
	TransferInverseTable = "transfers"
	// TransferColumn is the table column denoting the transfer relation/edge.
	TransferColumn = "cooperative_exit_transfer"
)

// Columns holds all SQL columns for cooperativeexit fields.
var Columns = []string{
	FieldID,
	FieldCreateTime,
	FieldUpdateTime,
	FieldExitTxid,
	FieldConfirmationHeight,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "cooperative_exits"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"cooperative_exit_transfer",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultCreateTime holds the default value on creation for the "create_time" field.
	DefaultCreateTime func() time.Time
	// DefaultUpdateTime holds the default value on creation for the "update_time" field.
	DefaultUpdateTime func() time.Time
	// UpdateDefaultUpdateTime holds the default value on update for the "update_time" field.
	UpdateDefaultUpdateTime func() time.Time
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// OrderOption defines the ordering options for the CooperativeExit queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByCreateTime orders the results by the create_time field.
func ByCreateTime(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreateTime, opts...).ToFunc()
}

// ByUpdateTime orders the results by the update_time field.
func ByUpdateTime(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUpdateTime, opts...).ToFunc()
}

// ByConfirmationHeight orders the results by the confirmation_height field.
func ByConfirmationHeight(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldConfirmationHeight, opts...).ToFunc()
}

// ByTransferField orders the results by transfer field.
func ByTransferField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newTransferStep(), sql.OrderByField(field, opts...))
	}
}
func newTransferStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(TransferInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, TransferTable, TransferColumn),
	)
}
