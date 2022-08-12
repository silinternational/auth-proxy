package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AuthSitesDecode(t *testing.T) {
	assert := assert.New(t)
	want := make(AuthSites)
	input := ""
	var got AuthSites

	// Test empty string
	err := got.Decode(input)
	assert.NoError(err)
	assertEqual(want, got)

	// Test multiple commas
	input += ",,"
	err = got.Decode(input)
	assert.NoError(err)
	assertEqual(want, got)

	// Test no colon
	input = "www.example.com"
	err = got.Decode(input)
	assert.ErrorContains(err, "invalid input format")

	// Test one value
	input = "one:http://example.com"
	want["one"] = "example.com:80"
	err = got.Decode(input)
	assert.NoError(err)
	assertEqual(want, got)

	// Test with port
	input += ",two:https://testing.com:7388"
	want["two"] = "testing.com:7388"
	err = got.Decode(input)
	assert.NoError(err)
	assertEqual(want, got)

	// Test no protocol
	input += ",three:go.dev"
	want["three"] = "go.dev:80"
	err = got.Decode(input)
	assert.NoError(err)
	assertEqual(want, got)

	// Test extra comma
	input += ","
	err = got.Decode(input)
	assert.NoError(err)
	assertEqual(want, got)
}
