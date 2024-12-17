src := rt-fib_fuzz_utils.c a-path_fuzz.c
obj := $(src-o-files)


fuzz_src := rt-fib_fuzz_positive_matches.c rt-fib_fuzz_mostly_negative_matches.c rt-fib_fuzz_only_negative_matches.c a-path_fuzz_match.c
fuzz_targets := $(fuzz_targets) $(fuzz-target-files)
fuzz_objs := $(fuzz_objs) $(src-o-files)
