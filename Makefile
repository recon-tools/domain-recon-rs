.PHONY: build build-release-tar build-release-zip check fmt install-local publish-all run-integration

build:
	cargo build

build-release-tar:
	cd $(target)-$(tag)-bin && \
		chmod +x domain-recon && \
		tar czvf domain-recon-$(tag).$(target).tar.gz domain-recon && \
		shasum -a 256 domain-recon-$(tag).$(target).tar.gz > domain-recon-$(tag).$(target).tar.gz.sha256 && \
		mv *.tar.gz* .. && cd ..

build-release-zip:
	cd $(target)-$(tag)-bin && \
		zip domain-recon-$(tag).$(target).zip domain-recon.exe && \
		shasum -a 256 domain-recon-$(tag).$(target).zip > domain-recon-$(tag).$(target).zip.sha256 && \
		mv *.zip* .. && cd ..

check:
	cargo check
	cargo +nightly udeps

fmt:
	cargo +nightly fmt --all
