export GO111MODULE=on

SBOM_NAME=package-sbom-tool

VERSION_FILE := pkg/version/version.go
CHANGELOG_FILE := debian/changelog
VERSION :=$(shell head -n 1 $(CHANGELOG_FILE) | cut -d ' ' -f 2 | cut -d '(' -f 2 |  cut -d ')' -f 1 | tr -d '\n')


all: build

update-version:
	@echo "Updating version from $(CHANGELOG_FILE) to $(VERSION_FILE)"
	@echo "tool version: $(VERSION)"
	@sed  -i 's/^const VERSION.*/const VERSION = "$(VERSION)"/' $(VERSION_FILE)
	@echo '$(VERSION_FILE) updated successfully'

build: update-version
	go build -o ${SBOM_NAME} cmd/${SBOM_NAME}/main.go 

clean:
	rm -rf ${SBOM_NAME}


.PHONY: update-version build clean
