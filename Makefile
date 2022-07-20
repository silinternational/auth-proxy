app:
	docker-compose up -d caddy

test: test-unit test-functional

test-unit:
	go test

test-functional:
	echo "not implemented"
