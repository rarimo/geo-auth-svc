package data

import "time"

type User struct {
	Nullifier   string    `db:"nullifier"`
	AnonymousID string    `db:"anonymous_id"`
	IsProven    bool      `db:"is_proven"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

type UsersQ interface {
	New() UsersQ
	Insert(User) error
	UpdateIsProven(bool) error

	Select() ([]User, error)
	Get() (*User, error)

	FilterByNullifier(nullifier string) UsersQ
	FilterByAnonymousID(id string) UsersQ
}
