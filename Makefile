# Makefile for SURF UFM PKey Daemon RPM package

NAME = surf-ufm-pkeyd
VERSION = 1.0.0
RELEASE = 1

# RPM build directories
RPMROOT = $(HOME)/rpmbuild
SOURCEDIR = $(RPMROOT)/SOURCES
SPECDIR = $(RPMROOT)/SPECS
SRPMDIR = $(RPMROOT)/SRPMS
RPMDIR = $(RPMROOT)/RPMS

# Files to include in source tarball
SOURCE_FILES = surf_ufm_pkeyd.py surf-ufm-pkeyd.service README.md requirements.txt

.PHONY: all clean rpm srpm prep tarball install

all: rpm

# Create RPM build directory structure
prep:
	@echo "Creating RPM build directories..."
	mkdir -p $(RPMROOT)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
tarball: prep
	@echo "Creating source tarball..."
	mkdir -p $(NAME)-$(VERSION)
	cp $(SOURCE_FILES) $(NAME)-$(VERSION)/
	tar czf $(SOURCEDIR)/$(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)/
	rm -rf $(NAME)-$(VERSION)
	cp $(NAME).spec $(SPECDIR)/

# Build source RPM
srpm: tarball
	@echo "Building source RPM..."
	rpmbuild -bs $(SPECDIR)/$(NAME).spec

# Build binary RPM
rpm: tarball
	@echo "Building RPM package..."
	rpmbuild -bb $(SPECDIR)/$(NAME).spec

# Install dependencies for building
install-deps:
	@echo "Installing build dependencies..."
	sudo dnf install -y rpm-build rpmdevtools python3-devel systemd-rpm-macros

# Setup RPM build environment
setup: install-deps prep
	@echo "RPM build environment ready"
	@echo "Build directory: $(RPMROOT)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(RPMROOT)/BUILD/$(NAME)-$(VERSION)
	rm -f $(SOURCEDIR)/$(NAME)-$(VERSION).tar.gz
	rm -f $(SPECDIR)/$(NAME).spec

# Show RPM info
info:
	@echo "Package: $(NAME)"
	@echo "Version: $(VERSION)-$(RELEASE)"
	@echo "Files:"
	@for file in $(SOURCE_FILES); do echo "  $$file"; done

# Quick test build (without installing)
test-build: tarball
	@echo "Testing RPM build (no install)..."
	rpmbuild --nobuild $(SPECDIR)/$(NAME).spec

help:
	@echo "Available targets:"
	@echo "  all         - Build RPM package (default)"
	@echo "  setup       - Install dependencies and setup build environment"
	@echo "  prep        - Create RPM build directories"
	@echo "  tarball     - Create source tarball"
	@echo "  srpm        - Build source RPM"
	@echo "  rpm         - Build binary RPM"
	@echo "  test-build  - Test build without installing"
	@echo "  clean       - Clean build artifacts"
	@echo "  info        - Show package information"
	@echo "  help        - Show this help message"