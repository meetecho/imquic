if ENABLE_DOCS

doxygendir = $(htmldir)/imquic-$(VERSION)

EXTRA_DIST = html

all: html-local

html-local:
	mkdir -p html
	doxygen imquic.cfg
	doxygen imquic-api.cfg
	doxygen imquic-internal.cfg
	cp doxy-boot.js html/
	mkdir -p html/css
	cp imquic.css html/css/
	cp favicon.ico html/
	cp meetecho-logo.png html/

install-data-local: html-local
	$(MKDIR_P) $(DESTDIR)$(doxygendir)
	cp -r html/ $(DESTDIR)$(doxygendir)

uninstall-local:
	rm -rf $(DESTDIR)$(doxygendir)

clean-local:
	rm -rf $(builddir)/html

endif
