BINARY := cloudctl
MAINMODULE := github.com/mwennrich/cloudctl
# the builder is at https://github.com/metal-stack/builder
COMMONDIR := $(or ${COMMONDIR},../../metal-stack/builder)

include $(COMMONDIR)/Makefile.inc

release:: all
