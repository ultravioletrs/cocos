docker_mfxkit:
	docker build --no-cache --tag=mainflux/mfxkit -f docker/Dockerfile .

run:
	docker-compose -f docker/docker-compose.yml up
