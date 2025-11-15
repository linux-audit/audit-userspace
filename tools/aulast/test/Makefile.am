CONFIG_CLEAN_FILES = *.loT *.rej *.orig
noinst_PROGRAMS = aulast_llist_test
TESTS = aulast_llist_test

AM_CPPFLAGS = -I${top_srcdir}/tools/aulast

aulast_llist_test_SOURCES = aulast_llist_test.c ${top_srcdir}/tools/aulast/aulast-llist.c
if HAVE_ASAN
aulast_llist_test_CFLAGS = ${ASAN_FLAGS}
aulast_llist_test_LDFLAGS = ${ASAN_FLAGS}
else
aulast_llist_test_LDFLAGS = -static
endif
