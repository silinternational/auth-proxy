dev:
	docker-compose up -d app

test: dev
	docker-compose up -d fakemanagementapi server1 server2 server3
	docker-compose run --rm test go test

clean:
	docker-compose kill
	docker-compose rm -f

fresh: clean dev
