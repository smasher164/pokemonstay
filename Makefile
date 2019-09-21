# TODO: Include MySQL in development and testing containers, but
#       allow deployment to use the one provided by CS 3250.
#
# TODO: Create testing build script.
#
# TODO: Pass config environment variables into containers.

run:
	# Run the command below to remove the image with the tag
	# 'stay:dev'from your system. I left it out here so that
	# local builds are faster.
	# - docker rmi -f stay:dev

	# Remove running container. '-' prefix indicates that it's okay
	# if the command produces an error, i.e. there is no running
	# container with the name 'staydev'.
	- docker rm -f staydev

	# Build the image with the Dockerfile in the current directory,
	# and tag it with 'stay:dev'.
	docker build . --tag stay:dev

	# Spawn a new container from the image tagged as 'stay:dev',
	# and give it the name 'staydev'.
	# '--rm' means to remove the container when it exits,
	# '-detach' means to run the container in the background,
	# '-p' means to map the host port 8080 to 8000 in the container.
	docker run --rm -detach -p 8080:8000 --name staydev stay:dev

deploy:
	# Run the command below to remove the image with the tag
	# 'stay:prod'from your system. I left it out here so that
	# local builds are faster.
	# - docker rmi -f stay:prod

	# Remove running container. '-' prefix indicates that it's okay
	# if the command produces an error, i.e. there is no running
	# container with the name 'stay'.
	- docker rm -f stay

	# Build the image with the Dockerfile in the current directory,
	# and tag it with 'stay:prod'.
	docker build . --tag stay:prod

	# Tag the local 'stay:prod' image into the smasher164 repository.
	docker tag stay:prod smasher164/stay:prod

	# Push the tagged image to the docker hub registry.
	docker push smasher164/stay:prod

	# SSH into VM, pull down the image, and restart the service.
	ssh core@akhil.cc "docker pull smasher164/stay:prod && sudo systemctl restart stay"

test:
	# nothing here yet.