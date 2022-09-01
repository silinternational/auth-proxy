dev:
	docker-compose up -d app

test:
	docker-compose run --rm test ./run-tests.sh

clean:
	docker-compose kill
	docker-compose rm -f

fresh: clean dev
