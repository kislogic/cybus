package dto

import "errors"

var (
	ErrEntityDeleteNotSuccessful = errors.New("entity for delete was not found")
	ErrEntityNotFound            = errors.New("entity not found in persistent storage by unique parameter")
	ErrDuplicateEntity           = errors.New("entity already exists in persistent storage")
)
