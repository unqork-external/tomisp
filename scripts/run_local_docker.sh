#!/bin/bash


#Initialize DB (do once)
#docker run -it --rm -v ~/docker/misp-db:/var/lib/mysql harvarditsecurity/misp /init-db

#Run it
docker run -it -d -p 443:443 -p 80:80 -p 3306:3306 -p 6666:6666 -v ~/docker/misp-db:/var/lib/mysql harvarditsecurity/misp
