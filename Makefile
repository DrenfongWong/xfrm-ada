PREFIX   ?= $(HOME)/libraries
LIBDIR    = lib
SRCDIR    = src
OBJDIR    = obj
GPR_FILES = gnat/*.gpr

THINDIR = thin
DUMMY  := $(shell mkdir -p $(THINDIR))

SRC_INCLUDE = /usr/include/linux/xfrm.h

BUILD_OPTS = -p

all: xfrm_lib

xfrm_lib: $(THINDIR)/xfrm_h.ads
	@gprbuild $(BUILD_OPTS) -P$@

$(THINDIR)/xfrm_h.ads : $(SRC_INCLUDE)
	cp $(SRC_INCLUDE) $(THINDIR)
	(cd thin && g++ -fdump-ada-spec xfrm.h)

install: install_lib install_static

install_lib: xfrm_lib
	install -d $(PREFIX)/lib/gnat
	install -d $(PREFIX)/lib/xfrm
	install -d $(PREFIX)/include/xfrm
	install -m 644 $(SRCDIR)/*.ad[bs] $(PREFIX)/include/xfrm
	install -m 644 $(THINDIR)/*.ads $(PREFIX)/include/xfrm
	install -m 444 $(LIBDIR)/*.ali $(PREFIX)/lib/xfrm
	install -m 644 $(GPR_FILES) $(PREFIX)/lib/gnat

install_static:
	install -m 444 $(LIBDIR)/libxfrmada.a $(PREFIX)/lib

clean:
	@rm -rf $(THINDIR)
	@rm -rf $(OBJDIR)
	@rm -rf $(LIBDIR)
