.PHONY: build build-release-tar build-release-zip check fmt install-local publish-all run-integration

build:
	cargo build

build-release-tar:
	cd $(target)-$(tag)-bin && \
		chmod +x domain-recon-rs && \
		tar czvf domain-recon-rs-$(tag).$(target).tar.gz domain-recon-rs && \
		shasum -a 256 domain-recon-rs-$(tag).$(target).tar.gz > domain-recon-rs-$(tag).$(target).tar.gz.sha256 && \
		mv *.tar.gz* .. && cd ..

build-release-zip:
	cd $(target)-$(tag)-bin && \
		zip domain-recon-rs-$(tag).$(target).zip domain-recon-rs.exe && \
		shasum -a 256 domain-recon-rs-$(tag).$(target).zip > domain-recon-rs-$(tag).$(target).zip.sha256 && \
		mv *.zip* .. && cd ..

check:
	cargo check
	cargo +nightly udeps

fmt:
	cargo +nightly fmt --all
