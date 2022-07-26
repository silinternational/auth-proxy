dev:
	docker-compose up -d app

test:
	docker-compose up -d testapp fakemanagementapi server1 server2 server3
	docker-compose run --rm test go test

clean:
	docker-compose kill
	docker-compose rm -f

fresh: clean dev
