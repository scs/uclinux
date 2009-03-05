# Requirements:
# - set VER to the package directory
# - set URL to the download URL

# dummy for include order
all:

A = $(DOWNLOADDIR)/$(notdir $(URL))
$(A):
	wget -c $(URL) -P $(dir $(A))
.PHONY: download
download: $(A)

P = )
DECOMP = $(shell \
	case $(A) in \
	*.gz   $(P) echo gzip -dc  ;; \
	*.bz2  $(P) echo bzip2 -dc ;; \
	*.lzma $(P) echo lzma -dc  ;; \
	*      $(P) echo cat       ;; \
	esac \
)

PATCH = patch -f -p1 -E --no-backup-if-mismatch
$(VER)/.unpacked: $(A)
	$(DECOMP) $< | tar xf -
ifneq (,$(wildcard $(CURDIR)/patches/*.patch))
	for p in $(CURDIR)/patches/*.patch ; do \
		( \
		echo " * Applying $$p ..." ; \
		cd $(VER) ; \
		$(PATCH) --dry-run < $$p >/dev/null || exit $$? ; \
		$(PATCH) < $$p ; \
		) || exit $$? ; \
	done
endif
	touch $(VER)/.unpacked
