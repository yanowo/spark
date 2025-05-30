// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/ent/predicate"
	"github.com/lightsparkdev/spark/so/ent/preimagerequest"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/ent/usersignedtransaction"
)

// UserSignedTransactionUpdate is the builder for updating UserSignedTransaction entities.
type UserSignedTransactionUpdate struct {
	config
	hooks    []Hook
	mutation *UserSignedTransactionMutation
}

// Where appends a list predicates to the UserSignedTransactionUpdate builder.
func (ustu *UserSignedTransactionUpdate) Where(ps ...predicate.UserSignedTransaction) *UserSignedTransactionUpdate {
	ustu.mutation.Where(ps...)
	return ustu
}

// SetUpdateTime sets the "update_time" field.
func (ustu *UserSignedTransactionUpdate) SetUpdateTime(t time.Time) *UserSignedTransactionUpdate {
	ustu.mutation.SetUpdateTime(t)
	return ustu
}

// SetTreeNodeID sets the "tree_node" edge to the TreeNode entity by ID.
func (ustu *UserSignedTransactionUpdate) SetTreeNodeID(id uuid.UUID) *UserSignedTransactionUpdate {
	ustu.mutation.SetTreeNodeID(id)
	return ustu
}

// SetTreeNode sets the "tree_node" edge to the TreeNode entity.
func (ustu *UserSignedTransactionUpdate) SetTreeNode(t *TreeNode) *UserSignedTransactionUpdate {
	return ustu.SetTreeNodeID(t.ID)
}

// SetPreimageRequestID sets the "preimage_request" edge to the PreimageRequest entity by ID.
func (ustu *UserSignedTransactionUpdate) SetPreimageRequestID(id uuid.UUID) *UserSignedTransactionUpdate {
	ustu.mutation.SetPreimageRequestID(id)
	return ustu
}

// SetPreimageRequest sets the "preimage_request" edge to the PreimageRequest entity.
func (ustu *UserSignedTransactionUpdate) SetPreimageRequest(p *PreimageRequest) *UserSignedTransactionUpdate {
	return ustu.SetPreimageRequestID(p.ID)
}

// Mutation returns the UserSignedTransactionMutation object of the builder.
func (ustu *UserSignedTransactionUpdate) Mutation() *UserSignedTransactionMutation {
	return ustu.mutation
}

// ClearTreeNode clears the "tree_node" edge to the TreeNode entity.
func (ustu *UserSignedTransactionUpdate) ClearTreeNode() *UserSignedTransactionUpdate {
	ustu.mutation.ClearTreeNode()
	return ustu
}

// ClearPreimageRequest clears the "preimage_request" edge to the PreimageRequest entity.
func (ustu *UserSignedTransactionUpdate) ClearPreimageRequest() *UserSignedTransactionUpdate {
	ustu.mutation.ClearPreimageRequest()
	return ustu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (ustu *UserSignedTransactionUpdate) Save(ctx context.Context) (int, error) {
	ustu.defaults()
	return withHooks(ctx, ustu.sqlSave, ustu.mutation, ustu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ustu *UserSignedTransactionUpdate) SaveX(ctx context.Context) int {
	affected, err := ustu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (ustu *UserSignedTransactionUpdate) Exec(ctx context.Context) error {
	_, err := ustu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ustu *UserSignedTransactionUpdate) ExecX(ctx context.Context) {
	if err := ustu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ustu *UserSignedTransactionUpdate) defaults() {
	if _, ok := ustu.mutation.UpdateTime(); !ok {
		v := usersignedtransaction.UpdateDefaultUpdateTime()
		ustu.mutation.SetUpdateTime(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ustu *UserSignedTransactionUpdate) check() error {
	if ustu.mutation.TreeNodeCleared() && len(ustu.mutation.TreeNodeIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "UserSignedTransaction.tree_node"`)
	}
	if ustu.mutation.PreimageRequestCleared() && len(ustu.mutation.PreimageRequestIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "UserSignedTransaction.preimage_request"`)
	}
	return nil
}

func (ustu *UserSignedTransactionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := ustu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(usersignedtransaction.Table, usersignedtransaction.Columns, sqlgraph.NewFieldSpec(usersignedtransaction.FieldID, field.TypeUUID))
	if ps := ustu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ustu.mutation.UpdateTime(); ok {
		_spec.SetField(usersignedtransaction.FieldUpdateTime, field.TypeTime, value)
	}
	if ustu.mutation.TreeNodeCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.TreeNodeTable,
			Columns: []string{usersignedtransaction.TreeNodeColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(treenode.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ustu.mutation.TreeNodeIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.TreeNodeTable,
			Columns: []string{usersignedtransaction.TreeNodeColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(treenode.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if ustu.mutation.PreimageRequestCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.PreimageRequestTable,
			Columns: []string{usersignedtransaction.PreimageRequestColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(preimagerequest.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ustu.mutation.PreimageRequestIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.PreimageRequestTable,
			Columns: []string{usersignedtransaction.PreimageRequestColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(preimagerequest.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, ustu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{usersignedtransaction.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	ustu.mutation.done = true
	return n, nil
}

// UserSignedTransactionUpdateOne is the builder for updating a single UserSignedTransaction entity.
type UserSignedTransactionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *UserSignedTransactionMutation
}

// SetUpdateTime sets the "update_time" field.
func (ustuo *UserSignedTransactionUpdateOne) SetUpdateTime(t time.Time) *UserSignedTransactionUpdateOne {
	ustuo.mutation.SetUpdateTime(t)
	return ustuo
}

// SetTreeNodeID sets the "tree_node" edge to the TreeNode entity by ID.
func (ustuo *UserSignedTransactionUpdateOne) SetTreeNodeID(id uuid.UUID) *UserSignedTransactionUpdateOne {
	ustuo.mutation.SetTreeNodeID(id)
	return ustuo
}

// SetTreeNode sets the "tree_node" edge to the TreeNode entity.
func (ustuo *UserSignedTransactionUpdateOne) SetTreeNode(t *TreeNode) *UserSignedTransactionUpdateOne {
	return ustuo.SetTreeNodeID(t.ID)
}

// SetPreimageRequestID sets the "preimage_request" edge to the PreimageRequest entity by ID.
func (ustuo *UserSignedTransactionUpdateOne) SetPreimageRequestID(id uuid.UUID) *UserSignedTransactionUpdateOne {
	ustuo.mutation.SetPreimageRequestID(id)
	return ustuo
}

// SetPreimageRequest sets the "preimage_request" edge to the PreimageRequest entity.
func (ustuo *UserSignedTransactionUpdateOne) SetPreimageRequest(p *PreimageRequest) *UserSignedTransactionUpdateOne {
	return ustuo.SetPreimageRequestID(p.ID)
}

// Mutation returns the UserSignedTransactionMutation object of the builder.
func (ustuo *UserSignedTransactionUpdateOne) Mutation() *UserSignedTransactionMutation {
	return ustuo.mutation
}

// ClearTreeNode clears the "tree_node" edge to the TreeNode entity.
func (ustuo *UserSignedTransactionUpdateOne) ClearTreeNode() *UserSignedTransactionUpdateOne {
	ustuo.mutation.ClearTreeNode()
	return ustuo
}

// ClearPreimageRequest clears the "preimage_request" edge to the PreimageRequest entity.
func (ustuo *UserSignedTransactionUpdateOne) ClearPreimageRequest() *UserSignedTransactionUpdateOne {
	ustuo.mutation.ClearPreimageRequest()
	return ustuo
}

// Where appends a list predicates to the UserSignedTransactionUpdate builder.
func (ustuo *UserSignedTransactionUpdateOne) Where(ps ...predicate.UserSignedTransaction) *UserSignedTransactionUpdateOne {
	ustuo.mutation.Where(ps...)
	return ustuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (ustuo *UserSignedTransactionUpdateOne) Select(field string, fields ...string) *UserSignedTransactionUpdateOne {
	ustuo.fields = append([]string{field}, fields...)
	return ustuo
}

// Save executes the query and returns the updated UserSignedTransaction entity.
func (ustuo *UserSignedTransactionUpdateOne) Save(ctx context.Context) (*UserSignedTransaction, error) {
	ustuo.defaults()
	return withHooks(ctx, ustuo.sqlSave, ustuo.mutation, ustuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ustuo *UserSignedTransactionUpdateOne) SaveX(ctx context.Context) *UserSignedTransaction {
	node, err := ustuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (ustuo *UserSignedTransactionUpdateOne) Exec(ctx context.Context) error {
	_, err := ustuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ustuo *UserSignedTransactionUpdateOne) ExecX(ctx context.Context) {
	if err := ustuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ustuo *UserSignedTransactionUpdateOne) defaults() {
	if _, ok := ustuo.mutation.UpdateTime(); !ok {
		v := usersignedtransaction.UpdateDefaultUpdateTime()
		ustuo.mutation.SetUpdateTime(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ustuo *UserSignedTransactionUpdateOne) check() error {
	if ustuo.mutation.TreeNodeCleared() && len(ustuo.mutation.TreeNodeIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "UserSignedTransaction.tree_node"`)
	}
	if ustuo.mutation.PreimageRequestCleared() && len(ustuo.mutation.PreimageRequestIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "UserSignedTransaction.preimage_request"`)
	}
	return nil
}

func (ustuo *UserSignedTransactionUpdateOne) sqlSave(ctx context.Context) (_node *UserSignedTransaction, err error) {
	if err := ustuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(usersignedtransaction.Table, usersignedtransaction.Columns, sqlgraph.NewFieldSpec(usersignedtransaction.FieldID, field.TypeUUID))
	id, ok := ustuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "UserSignedTransaction.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := ustuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, usersignedtransaction.FieldID)
		for _, f := range fields {
			if !usersignedtransaction.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != usersignedtransaction.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := ustuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ustuo.mutation.UpdateTime(); ok {
		_spec.SetField(usersignedtransaction.FieldUpdateTime, field.TypeTime, value)
	}
	if ustuo.mutation.TreeNodeCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.TreeNodeTable,
			Columns: []string{usersignedtransaction.TreeNodeColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(treenode.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ustuo.mutation.TreeNodeIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.TreeNodeTable,
			Columns: []string{usersignedtransaction.TreeNodeColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(treenode.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if ustuo.mutation.PreimageRequestCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.PreimageRequestTable,
			Columns: []string{usersignedtransaction.PreimageRequestColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(preimagerequest.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ustuo.mutation.PreimageRequestIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   usersignedtransaction.PreimageRequestTable,
			Columns: []string{usersignedtransaction.PreimageRequestColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(preimagerequest.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &UserSignedTransaction{config: ustuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, ustuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{usersignedtransaction.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	ustuo.mutation.done = true
	return _node, nil
}
