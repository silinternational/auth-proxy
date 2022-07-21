Feature: functional test cases
	Scenario: No authorization data
		When we send a request with no authorization data
		Then we will be redirected

	Scenario: Invalid authorization data
		When we sent a request with invalid authorization data
		Then we will see an error message

	Scenario Outline: Authorization data specifying various levels of access
		When we send a request with valid authorization data authorizing <accessLevel> access
		Then we will see the <accessLevel> version of the website

		Examples:
			| accessLevel |
			| one         |
			| two         |
			| ten         |
