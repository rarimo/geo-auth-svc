package pg

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/rarimo/geo-auth-svc/internal/data"
	"gitlab.com/distributed_lab/kit/pgdb"
)

const usersTable = "users"

type usersQ struct {
	db       *pgdb.DB
	selector squirrel.SelectBuilder
	updater  squirrel.UpdateBuilder
}

func NewUsersQ(db *pgdb.DB) data.UsersQ {
	return &usersQ{
		db:       db,
		selector: squirrel.Select("*").From(usersTable),
		updater:  squirrel.Update(usersTable),
	}
}

func (q *usersQ) New() data.UsersQ {
	return NewUsersQ(q.db)
}

func (q *usersQ) Insert(user data.User) error {
	stmt := squirrel.Insert(usersTable).SetMap(map[string]interface{}{
		"nullifier":    user.Nullifier,
		"anonymous_id": user.AnonymousID,
		"is_proven":    user.IsProven,
	})

	if err := q.db.Exec(stmt); err != nil {
		return fmt.Errorf("insert user %+v: %w", user, err)
	}

	return nil
}

func (q *usersQ) UpdateIsProven(proven bool) error {
	if err := q.db.Exec(q.updater.Set("is_proven", proven)); err != nil {
		return fmt.Errorf("update user is_proven: %w", err)
	}

	return nil
}

func (q *usersQ) Select() ([]data.User, error) {
	var res []data.User

	if err := q.db.Select(&res, q.selector); err != nil {
		return nil, fmt.Errorf("select user: %w", err)
	}

	return res, nil
}

func (q *usersQ) Get() (*data.User, error) {
	var res data.User

	if err := q.db.Get(&res, q.selector); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	return &res, nil
}

func (q *usersQ) FilterByNullifier(nullifier string) data.UsersQ {
	return q.applyCondition(squirrel.Eq{"nullifier": nullifier})
}

func (q *usersQ) FilterByAnonymousID(id string) data.UsersQ {
	return q.applyCondition(squirrel.Eq{"anonymous_id": id})
}

func (q *usersQ) applyCondition(cond squirrel.Sqlizer) data.UsersQ {
	q.selector = q.selector.Where(cond)
	q.updater = q.updater.Where(cond)
	return q
}
