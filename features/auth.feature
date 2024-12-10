Feature: functional test cases
	Scenario: No authorization data
		When we send a request with no authorization data
		Then we do not see an error message
		And we will be redirected to the management api

	Scenario: Expired authorization data
		When we send a request with expired authorization data
		Then we do not see an error message
		And we will be redirected to the management api

	Scenario: Invalid authorization data
		When we send a request with invalid authorization data
		Then we do not see an error message
		And we will be redirected to the management api

	Scenario Outline: Authorization data specifying various levels of access
		When we send a request with authorization data in the <urlOrCookie> authorizing <accessLevel> access
		Then we do not see an error message
		And we will see the <accessLevel> version of the website

		Examples:
			| urlOrCookie | accessLevel |
			| cookie      | one         |
			| cookie      | two         |
			| cookie      | three       |
			| url         | one         |
			| url         | two         |
			| url         | three       |

	Scenario: Trusted bot
		When we send a request with a user-agent that is trusted
		Then we do not see an error message
		And we will see the default version of the website
