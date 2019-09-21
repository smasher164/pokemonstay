#!/bin/bash
docker rmi -f smasher164/stay:prod
docker rm -f stay
docker run --name="stay" -p 8085:8000 smasher164/stay:prod