build-test-image:
	docker build -t docker.io/mvasek/docker-ssh-helper-test-img testdata/

test:
	go test -v ./...