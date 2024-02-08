package dto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrCacheMiss is a replacement for implementation defined cache miss error of different providers,
	// such as replacement for redis.Nil which looks cryptic.
	ErrCacheMiss = errors.New("cache: key not found")
)

// Cache is an interface which abstracts cache providers.
type Cache interface {

	// Get retrieves value from cache
	// returns ErrCacheMiss (if everything is ok, but value is not in cache)
	// or implementation defined error in case of problem.
	Get(ctx context.Context, key string, ptrValue interface{}) error

	Del(ctx context.Context, keys ...string) error

	// Set just sets the given key/value in the cache, overwriting any existing value
	// associated with that key.
	Set(ctx context.Context, key string, ptrValue interface{}, expires time.Duration) error
}

// Serialize performs the following logic:
//   - If value is a byte array, it is returned as-is
//   - Else, jsoniter is used to serialize.
func Serialize(value interface{}) ([]byte, error) {

	if data, ok := value.([]byte); ok {
		return data, nil
	}

	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Deserialize transforms bytes produced by Serialize back into a Go object,
// storing it into "ptr", which must be a pointer to the value type.
func Deserialize(byt []byte, ptr interface{}) error {

	if data, ok := ptr.(*[]byte); ok {
		*data = byt
		return nil
	}

	b := bytes.NewBuffer(byt)
	decoder := json.NewDecoder(b)
	if err := decoder.Decode(ptr); err != nil {
		return err
	}

	return nil
}
