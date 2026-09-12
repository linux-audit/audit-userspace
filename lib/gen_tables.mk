# The including Makefiles list only table generators in noinst_PROGRAMS.
# These programs run on the build machine, even when cross-compiling.
# Replace Automake's host executable suffix with the build-machine suffix.
table_gen_programs = $(noinst_PROGRAMS:$(EXEEXT)=)
# Automake replaces hyphens with underscores in per-program variable names.
# Apply the flags to objects too, so direct object builds use the same compiler.
table_gen_targets = $(addsuffix $(BUILD_EXEEXT),$(table_gen_programs)) \
	$(foreach prog,$(subst -,_,$(table_gen_programs)),$($(prog)_OBJECTS))
$(table_gen_targets): CC = $(CC_FOR_BUILD)
$(table_gen_targets): CFLAGS = $(CFLAGS_FOR_BUILD)
$(table_gen_targets): CPPFLAGS = $(CPPFLAGS_FOR_BUILD)
$(table_gen_targets): LDFLAGS = $(LDFLAGS_FOR_BUILD)
