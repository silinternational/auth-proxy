package proxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	p    Proxy
	last testResponse

	client = http.DefaultClient
)

func Test_Functional(t *testing.T) {
	// run functional tests
	status := godog.TestSuite{
		Name:                 "functional tests",
		ScenarioInitializer:  InitializeScenario,
		TestSuiteInitializer: InitializeTestSuite,
	}.Run()

	assert.Equal(t, 0, status, "One or more functional tests failed.")
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
	c := makeTestJWTCookie(p.CookieName, p.Secret, level, time.Now().AddDate(0, 0, 1))
	return sendRequest(p.Host, c)
}

func weSendARequestWithAuthorizationData(t string) error {
	var c *http.Cookie
	switch t {
	case "expired":
		c = makeTestJWTCookie(p.CookieName, p.Secret, "level", time.Now().AddDate(0, 0, -1))
	case "invalid":
		c = makeTestJWTCookie(p.CookieName, []byte("bad"), "level", time.Now().AddDate(0, 0, 1))
	case "no":
		c = nil
	default:
		return godog.ErrPending
	}
	return sendRequest(p.Host, c)
}

func weWillBeRedirectedToTheManagementApi() error {
	return assertEqual("API -- ", last.body[:7],
		`did not see "API --" in the response body: %s`, last.body)
}

func weDoNotSeeAnErrorMessage() error {
	return assertEqual(http.StatusOK, last.response.StatusCode)
}

func weWillSeeAnErrorMessage() error {
	return assertEqual(http.StatusInternalServerError, last.response.StatusCode,
		"expected a 500, --%s-- got a %d, body: %s", p.Host, last.response.StatusCode, last.body)
}

func weWillSeeTheAccessLevelVersionOfTheWebsite(level string) error {
	proxy := last
	if err := sendRequest("http://"+p.Sites[level], nil); err != nil {
		return err
	}

	return assertEqual(last.body, proxy.body)
}

func InitializeTestSuite(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		var err error
		if p, err = newProxy(); err != nil {
			panic(err.Error())
		}
	})
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
type asserter struct {
	err error
}

// Errorf is used by the called assertion to report an error
func (a *asserter) Errorf(format string, args ...interface{}) {
	a.err = fmt.Errorf(format, args...)
}

func assertEqual(expected, actual interface{}, msgAndArgs ...interface{}) error {
	var a asserter
	assert.Equal(&a, expected, actual, msgAndArgs...)
	return a.err
}
