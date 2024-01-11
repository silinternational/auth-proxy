package proxy

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
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

	// Any test initialization should be done in Godog hooks, e.g.: InitializeTestSuite or InitializeScenario

	assert.Equal(t, 0, status, "One or more functional tests failed.")
}

func InitializeTestSuite(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		var err error
		if p, err = newProxy(); err != nil {
			panic(err.Error())
		}
		client.Jar, _ = cookiejar.New(nil)
	})
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	ctx.Step(`^we send a request with (\w+) authorization data$`, weSendARequestWithAuthorizationData)
	ctx.Step(`^we send a request with authorization data in the (\w+) authorizing (\w+) access$`,
		weSendARequestWithAuthorizationDataAuthorizingAccess)
	ctx.Step(`^we will be redirected to the management api$`, weWillBeRedirectedToTheManagementApi)
	ctx.Step(`^we do not see an error message$`, weDoNotSeeAnErrorMessage)
	ctx.Step(`^we will see an error message$`, weWillSeeAnErrorMessage)
	ctx.Step(`^we will see the (\w+) version of the website$`, weWillSeeTheAccessLevelVersionOfTheWebsite)
	ctx.Step(`^we do not see the token parameter$`, weDoNotSeeTheTokenParameter)
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
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	last = testResponse{response, string(body)}
	return nil
}

func weSendARequestWithAuthorizationDataAuthorizingAccess(where, level string) error {
	var c *http.Cookie
	url := p.Host
	expires := time.Now().Add(1000 + time.Second*time.Duration(rand.Intn(1000)))
	token := makeTestJWT(p.Secret, level, expires)

	if where == "cookie" {
		c = makeTestJWTCookie(p.CookieName, token)
	} else {
		url += fmt.Sprintf("?%s=%s", p.TokenParam, token)
	}
	return sendRequest(url, c)
}

func weSendARequestWithAuthorizationData(t string) error {
	var c *http.Cookie
	switch t {
	case "expired":
		token := makeTestJWT(p.Secret, "level", time.Now().AddDate(0, 0, -1))
		c = makeTestJWTCookie(p.CookieName, token)
	case "invalid":
		token := makeTestJWT([]byte("bad"), "level", time.Now().AddDate(0, 0, 1))
		c = makeTestJWTCookie(p.CookieName, token)
	case "no":
		c = nil
	default:
		return godog.ErrPending
	}
	return sendRequest(p.Host, c)
}

func weWillBeRedirectedToTheManagementApi() error {
	return assertContains(last.body, "<title>API</title>",
		`did not see "API" in the response body title: %s`, last.body)
}

func weDoNotSeeAnErrorMessage() error {
	return assertEqual(http.StatusOK, last.response.StatusCode, "incorrect http status, body=%s", last.body)
}

func weWillSeeAnErrorMessage() error {
	return assertEqual(http.StatusBadRequest, last.response.StatusCode,
		"expected a 400, --%s-- got a %d, body: %s", p.Host, last.response.StatusCode, last.body)
}

func weWillSeeTheAccessLevelVersionOfTheWebsite(level string) error {
	proxy := last
	if err := sendRequest("http://"+p.Sites[level], nil); err != nil {
		return err
	}

	return assertEqual(last.body, proxy.body)
}

func weDoNotSeeTheTokenParameter() error {
	token := last.response.Request.URL.Query().Get(p.TokenParam)
	return assertEqual("", token)
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

func assertContains(s, contains interface{}, msgAndArgs ...interface{}) error {
	var a asserter
	assert.Contains(&a, s, contains, msgAndArgs...)
	return a.err
}
