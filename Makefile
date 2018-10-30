CFLAGS += -O2
ARCH=$(shell uname -m)
OBJDIR ?= obj/$(ARCH)
PREFIX ?= /usr/local
NAME=deswappify
INSTPATH=$(PREFIX)/bin

VERSION=1.1
RELEASE=1

SRCS += $(shell find *.c)

OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

OUTPUT = ${OBJDIR}/$(NAME)

all: $(OUTPUT)

$(OBJS): Makefile

$(OUTPUT): $(OBJS)

$(OBJDIR)/%.o: %.c	Makefile
	@echo "Compiling $< to $@"
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(OBJDIR)/%:
	@echo "Linking $@"
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(filter %.o %.a,$+) $(LIBDIR) $(LIBRARIES)

clean:
	@rm -f $(OBJDIR)/*

install: $(OUTPUT)
	@mkdir -p $(INSTPATH)
	cp -d $(OUTPUT) $(INSTPATH)

$(OBJDIR)/$(NAME)-$(VERSION):
	@mkdir -p $(OBJDIR)/$(NAME)-$(VERSION)

$(OBJDIR)/$(NAME)-$(VERSION)/$(NAME).spec: $(OBJDIR)/$(NAME)-$(VERSION) $(NAME).spec Makefile
	@echo "Installing RPM specfile $@"
	@cat $(NAME).spec | sed -e 's/_RPM_VERSION/$(VERSION)/;s/_RPM_RELEASE/$(RELEASE)/' > $@

.PHONY: $(RPMBIN)

$(RPMBIN): $(OBJDIR)/$(NAME)-$(VERSION)/$(NAME).spec 
	tar -c --exclude=.git --exclude=*.spec --exclude=*~ --exclude=obj * | (cd $(OBJDIR)/$(NAME)-$(VERSION); tar xf -)
	(cd $(OBJDIR); tar cvz $(NAME)-$(VERSION)) > $(RPMBIN)

srcrpm: $(RPMBIN)
	rpmbuild -ts $(RPMBIN)
