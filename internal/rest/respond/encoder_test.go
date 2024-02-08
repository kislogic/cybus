package respond

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testdata = map[string]interface{}{"test": true}

func TestJSONEncoder(t *testing.T) {

	w := httptest.NewRecorder()

	assert.Equal(t, JSON.ContentType(), "application/json; charset=utf-8")
	assert.NoError(t, JSON.Encode(w, testdata))

	var actualData map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &actualData))
	assert.Equal(t, testdata, actualData)
}
