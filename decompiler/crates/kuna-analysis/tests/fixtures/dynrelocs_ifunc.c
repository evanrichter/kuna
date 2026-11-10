/* A GOT slot bound to an STT_GNU_IFUNC symbol holds what its resolver returns,
   not the resolver; plain is the control, an ordinary defined function. */
static int impl(void) { return 7; }
static void *pick(void) { return impl; }
int chosen(void) __attribute__((ifunc("pick")));
int plain(void) { return 3; }
int (*get_chosen(void))(void) { return chosen; }
int (*get_plain(void))(void) { return plain; }
