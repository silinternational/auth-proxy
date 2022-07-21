package proxy

import "github.com/cucumber/godog"

func weSendARequestWithNoAuthorizationData() error {
	return godog.ErrPending
}

func weSendARequestWithValidAuthorizationDataAuthorizingAccess(level string) error {
	return godog.ErrPending
}

func weSentARequestWithInvalidAuthorizationData() error {
	return godog.ErrPending
}

func weWillBeRedirected() error {
	return godog.ErrPending
}

func weWillSeeAnErrorMessage() error {
	return godog.ErrPending
}

func weWillSeeTheAccessLevelVersionOfTheWebsite(level string) error {
	return godog.ErrPending
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	ctx.Step(`^we send a request with no authorization data$`, weSendARequestWithNoAuthorizationData)
	ctx.Step(`^we send a request with valid authorization data authorizing (\w+) access$`, weSendARequestWithValidAuthorizationDataAuthorizingAccess)
	ctx.Step(`^we sent a request with invalid authorization data$`, weSentARequestWithInvalidAuthorizationData)
	ctx.Step(`^we will be redirected$`, weWillBeRedirected)
	ctx.Step(`^we will see an error message$`, weWillSeeAnErrorMessage)
	ctx.Step(`^we will see the (\w+) version of the website$`, weWillSeeTheAccessLevelVersionOfTheWebsite)
}
