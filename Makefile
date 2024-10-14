dev:
	docker compose up -d app fakemanagementapi server1 server2 server3

test:
	docker-compose run --rm test ./run-tests.sh

clean:
	docker compose kill
	docker compose rm -f

fresh: clean dev
