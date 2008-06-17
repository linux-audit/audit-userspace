#include <stdio.h>
#include <signal.h>
#include <syslog.h>

/* This is an example program that shows how easy it is to
 * write a audispd plugin. It shows the basic items that a
 * plugin is expected to follow. You should handle SIGTERM
 * and SIGHUP. The events come from stdin.
 */

/* Global Data */
volatile int stop = 0;
volatile int hup = 0;

/*
 * SIGTERM handler
 */
static void term_handler( int sig )
{
        stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler( int sig )
{
        hup = 1;
}

static void load_config(void)
{
	hup = 0;
}

int main(int argc, char *argv[])
{
	char tmp[1025];
	char *p = " ";
	struct sigaction sa;

	/* This plugin takes 1 argument to tell you which plugin it is */
	if (argc > 1)
		p = argv[1];

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

	do {
		/* Load configuration */
		load_config();

		/* Now the event loop */
		while (fgets(tmp, 1024, stdin) && hup==0 && stop==0)
			syslog(LOG_ERR, "plugin%s: %s", p, tmp);
	} while (hup && stop == 0);
	return 0;
}

