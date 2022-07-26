package proxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/stretchr/testify/assert"
)

type testResponse struct {
	response *http.Response
	body     string
}

var (
	auth ProxyAuth
	last testResponse

	client = http.DefaultClient
)

const testURL = "http://testapp:8888"

func Test_Functional(t *testing.T) {
	// setup
	var err error
	auth, err = newProxyAuth()
	assert.NoError(t, err)

	// run function tests
	status := godog.TestSuite{
		Name:                "godogs",
		ScenarioInitializer: InitializeScenario,
	}.Run()

	assert.Equal(t, 0, status)
}

func sendRequest(url string, c *http.Cookie) error {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	if c != nil {
		request.AddCookie(c)
	}

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	last = testResponse{response, string(body)}
	return nil
}

func weSendARequestWithValidAuthorizationDataAuthorizingAccess(level string) error {
	c := makeTestJWTCookie(auth.CookieName, auth.TokenSecret, level, time.Now().AddDate(0, 0, 1))
	return sendRequest(testURL, c)
}

func weSendARequestWithAuthorizationData(t string) error {
	var c *http.Cookie
	switch t {
	case "expired":
		c = makeTestJWTCookie(auth.CookieName, auth.TokenSecret, "level", time.Now().AddDate(0, 0, -1))
	case "invalid":
		c = makeTestJWTCookie(auth.CookieName, "bad", "level", time.Now().AddDate(0, 0, 1))
	case "no":
		c = nil
	default:
		return godog.ErrPending
	}
	return sendRequest(testURL, c)
}

func weWillBeRedirectedToTheManagementApi() error {
	proxy := last
	if err := sendRequest("http://"+os.Getenv("MANAGEMENT_API"), nil); err != nil {
		return err
	}

	return assertExpectedAndActual(assert.Equal, last.body, proxy.body)
}

func weDoNotSeeAnErrorMessage() error {
	return assertExpectedAndActual(assert.Equal, 200, last.response.StatusCode)
}

func weWillSeeAnErrorMessage() error {
	return assertExpectedAndActual(assert.Equal, 500, last.response.StatusCode)
}

func weWillSeeTheAccessLevelVersionOfTheWebsite(level string) error {
	proxy := last
	if err := sendRequest("http://"+auth.URLs[level], nil); err != nil {
		return err
	}

	return assertExpectedAndActual(assert.Equal, last.body, proxy.body)
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	ctx.Step(`^we send a request with (\w+) authorization data$`, weSendARequestWithAuthorizationData)
	ctx.Step(`^we send a request with valid authorization data authorizing (\w+) access$`, weSendARequestWithValidAuthorizationDataAuthorizingAccess)
	ctx.Step(`^we will be redirected to the management api$`, weWillBeRedirectedToTheManagementApi)
	ctx.Step(`^we do not see an error message$`, weDoNotSeeAnErrorMessage)
	ctx.Step(`^we will see an error message$`, weWillSeeAnErrorMessage)
	ctx.Step(`^we will see the (\w+) version of the website$`, weWillSeeTheAccessLevelVersionOfTheWebsite)
}

// Helper functions

// assertExpectedAndActual is a helper function to allow the step function to call
// assertion functions where you want to compare an expected and an actual value.
func assertExpectedAndActual(a expectedAndActualAssertion, expected, actual interface{}, msgAndArgs ...interface{}) error {
	var t asserter
	a(&t, expected, actual, msgAndArgs...)
	return t.err
}

type expectedAndActualAssertion func(t assert.TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool

// assertActual is a helper function to allow the step function to call
// assertion functions where you want to compare an actual value to a
// predined state like nil, empty or true/false.
func assertActual(a actualAssertion, actual interface{}, msgAndArgs ...interface{}) error {
	var t asserter
	a(&t, actual, msgAndArgs...)
	return t.err
}

type actualAssertion func(t assert.TestingT, actual interface{}, msgAndArgs ...interface{}) bool

// asserter is used to be able to retrieve the error reported by the called assertion
type asserter struct {
	err error
}

// Errorf is used by the called assertion to report an error
func (a *asserter) Errorf(format string, args ...interface{}) {
	a.err = fmt.Errorf(format, args...)
}
