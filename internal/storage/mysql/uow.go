package mysql

import (
	"context"
	"cybus/internal/dto"
	"cybus/internal/uow"
	"database/sql"
	"fmt"

	"go.uber.org/zap"
)

type unitOfWork struct {
	tx                 *sql.Tx
	t                  uow.Type
	userStorage        dto.UserStorage
	sessionStorage     dto.SessionStorage
	userSessionStorage dto.UserSessionStorage
	sessDeactivations  dto.SessionDeactivationsStorage
}

type key struct{}

var uowKey key

// NewUOW returns an implementation of the interface uow.StartUnitOfWork
// that will track all the postgres repositories
func NewUOW(db *sql.DB, logger *zap.Logger) uow.StartUnitOfWork {
	return func(ctx context.Context, t uow.Type, uowFn uow.UnitOfWorkFn, storages ...interface{}) (err error) {
		uw := &unitOfWork{t: t}
		if ctxOUW, ok := ctx.Value(uowKey).(*unitOfWork); ok {
			for i := range storages {
				if err := ctxOUW.add(storages[i]); err != nil {
					return fmt.Errorf("could not add reposotory: %w", err)
				}
			}
			ctx = context.WithValue(ctx, uowKey, ctxOUW)
			return uowFn(ctx, ctxOUW)
		}

		ctx = context.WithValue(ctx, uowKey, uw)
		err = uw.begin(ctx, db)
		if err != nil {
			return fmt.Errorf("could not initialize TX: %w", err)
		}
		defer func() {
			if r := recover(); r != nil {
				if rollBackErr := uw.rollback(); rollBackErr != nil {
					logger.Error("problem while trying to rollback after recover in transaction", zap.Error(rollBackErr))
				}
				panic(r)
			}

			rollbackErr := uw.rollback()
			if rollbackErr != nil && rollbackErr != sql.ErrTxDone {
				err = fmt.Errorf("failed to rollback TX: %s", rollbackErr)
			}
		}()

		for i := range storages {
			if err := uw.add(storages[i]); err != nil {
				return fmt.Errorf("could not add reposotory: %s", err)
			}
		}

		defer func() {
			if err == nil {
				commitErr := uw.commit()
				if commitErr != nil {
					err = fmt.Errorf("failed to commit TX: %s", commitErr)
				}
			}
		}()

		return uowFn(ctx, uw)
	}

}

func (uw *unitOfWork) commit() error { return uw.tx.Commit() }

func (uw *unitOfWork) rollback() error { return uw.tx.Rollback() }

func (uw *unitOfWork) begin(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	uw.tx = tx
	return nil
}

func (uw *unitOfWork) UserSessions() dto.UserSessionStorage { return uw.userSessionStorage }

func (uw *unitOfWork) SessionDeactivations() dto.SessionDeactivationsStorage {
	return uw.sessDeactivations
}

func (uw *unitOfWork) Sessions() dto.SessionStorage { return uw.sessionStorage }

func (uw *unitOfWork) Users() dto.UserStorage { return uw.userStorage }

func (uw *unitOfWork) add(r interface{}) error {

	switch rep := r.(type) {

	case *userStorage:
		if uw.userStorage == nil {
			r := *rep
			r.db = uw.tx
			uw.userStorage = &r
		}
		return nil

	case *sessionStorage:
		if uw.sessionStorage == nil {
			r := *rep
			r.db = uw.tx
			uw.sessionStorage = &r
		}
		return nil

	case *userSessionStorage:
		if uw.userSessionStorage == nil {
			r := *rep
			r.db = uw.tx
			uw.userSessionStorage = &r
		}
		return nil

	case *sessionDeactivationStorage:
		if uw.sessDeactivations == nil {
			r := *rep
			r.db = uw.tx
			uw.sessDeactivations = &r
		}
		return nil

	default:
		return fmt.Errorf("invalid repository of type: %T", rep)

	}
}
