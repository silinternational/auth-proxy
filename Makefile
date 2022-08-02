dev:
	docker-compose up -d app

test:
	docker-compose run --rm test go test

clean:
	docker-compose kill
	docker-compose rm -f

fresh: clean dev
