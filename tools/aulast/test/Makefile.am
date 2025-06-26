CONFIG_CLEAN_FILES = *.loT *.rej *.orig
noinst_PROGRAMS = aulast_llist_test
TESTS = aulast_llist_test

AM_CPPFLAGS = -I${top_srcdir}/tools/aulast

aulast_llist_test_SOURCES = aulast_llist_test.c ${top_srcdir}/tools/aulast/aulast-llist.c
aulast_llist_test_LDFLAGS = -static
