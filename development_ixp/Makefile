up:
	make -C netbox-docker up
	make -C virtual_network up
	make -C monitoring up
	make -C libreixp bootstrap

down:
	make -C netbox-docker down
	make -C virtual_network down
	make -C monitoring down
	make -C libreixp down

install_netbox_docker:
	git subtree add \
		--squash \
		-m "Add netbox-community/netbox-docker subtree" \
		--prefix=development_ixp/netbox-docker \
		git@github.com:netbox-community/netbox-docker.git \
		release
