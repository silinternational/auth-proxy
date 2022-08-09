dev:
	docker-compose up -d app

test:
	docker-compose run --rm test go install "github.com/cucumber/godog/cmd/godog@latest" && go test

clean:
	docker-compose kill
	docker-compose rm -f

fresh: clean dev
