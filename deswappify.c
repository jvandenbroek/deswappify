/*
deswappify - deswappify.c
(C) 2018 Joost van den Broek - jvandenbroek@gmail.com
Released under the GNU GPL, see the COPYING file
in the source distribution for its full text.
*/

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>

#define VERSION "0.2"

static char quiet = 0;
static int max_pid = 0;
static int bufsize = 4;
static struct rlimit rl;

int displayhelp(char **argv)
{
	printf("Usage: \n %s [options]\n\n", argv[0]);
	printf(
		"Basic options:\n"
		" -a\t\tall processes\n"
		" -p\t\tone or more PIDs seperated by space\n"
		" -q\t\tsuppress standard output\n"
		" -qq\t\tsuppress all output, including errors\n"
		" -v\t\tprint version info\n"
		" -b\t\tbuffer size in kB for fetching pages (default and minimum is 4)\n");
	exit(1);
}

int displayversion()
{
	printf(" deswappify %s\n", VERSION);
}

char **processall(char **proclist)
{
	DIR *d = NULL;
	struct dirent *ent;
	char dirname[] = "/proc/";
	int i = 0;

	if (!(d = opendir(dirname)))
	{
		fprintf(stderr, "error opening /proc directory\n");
		exit(1);
	}

	if (!(proclist = malloc((max_pid > 1000 ? 1000 : max_pid) * sizeof(proclist))))
		return NULL;

	char count = 0;
	for (; max_pid != 0; max_pid /= 10)
		count++;

	while ((ent = readdir(d)) != NULL)
	{
		if (ent->d_type == DT_DIR && ent->d_name[0] >= '0' && ent->d_name[0] <= '9')
		{
			if (!(proclist[i] = malloc(count + 1)))
				return NULL;
			strncpy(proclist[i], ent->d_name, count + 1);
			i++;
			if (i % 1000 == 0)
			{
				if (!(proclist = realloc(*proclist, (i + 1000) * sizeof(proclist))))
					return NULL;
			}
		}
	}
	proclist[i] = NULL;
	closedir(d);
	return proclist;
}

char **parsearg(int argc, char **argv, char **proclist)
{
	int help = 0;
	int i = 1;

	for(; i < argc; ++i)
	{
		const char *thisargv = argv[i];
		if(thisargv[0] == '-')
		{
 			int np = i + 1;
			if(np > argc)
			{
				help = 1;
				break;
			}
			switch(thisargv[1])
			{
			case 'a':
				if (thisargv[2] == '\0')
				{
					if (!(proclist = processall(proclist)))
						return NULL;
				}
				else
					help = 1;
				break;
			case 'p':
			{
				if (argc <= np || thisargv[2] != '\0')
					help = 1;
				else
				{
					int ii = 0;
					if (!(proclist = malloc(sizeof(proclist) * (argc - 1))))
						return NULL;

					if (*argv[np] != '-')
					{
						for (; np < argc && *argv[np] != '-'; ++np)
						{
							// only allow digits for PID
							int iii = 0;
							for (; argv[np][iii] != '\0'; ++iii)
							{
								if (argv[np][iii] < '0' || argv[np][iii] > '9')
								{
									help = 1;
									break;
								}
							}
							if (help)
								break;
							if (!(proclist[ii] = malloc(iii + 1)))
								return NULL;
							strncpy(proclist[ii], argv[np], iii + 1);
							i++;
							ii++;
						}
						if (argc < np)
							i--;
					}
					proclist[ii] = NULL;
				}
			}
				break;
			case 'q':
				if (thisargv[2] == 'q' && thisargv[3] == '\0')
					quiet = 2;
				else if (thisargv[2] == '\0')
					quiet = 1;
				else
					help = 1;
				break;
			case 'v':
				displayversion();
				exit(0);
				break;
			case 'b':
				if (argc <= np || thisargv[2] != '\0')
					help = 1;
				else
				{
					int ii = 0;
					if (argv[np][0] != '-')
					{
						for (; argv[np][ii] != '\0'; ++ii)
						{
							if (argv[np][ii] < '0' || argv[np][ii] > '9')
							{
								help = 1;
								break;
							}
						}
						int temp = atoi(argv[np]);
						getrlimit (RLIMIT_STACK, &rl);
						if (rl.rlim_cur / 2048 < temp)
						{
							printf("Max %dkB buffer size is allowed on stack (increase with ulimit -s)\n", (int)rl.rlim_cur / 2048);
							exit(1);
						}
						if (temp % 4 != 0)
						{
							help = 1;
							break;
						}
						bufsize = temp;
						i++;
						if (argc < np)
							i--;
					}
				}
				break;
			default:
				help = 1;
				break;
			}
		}
		else
		{
			help = 1;
		}
	}
	if (help)
		displayhelp(argv);

	return proclist;
}

unsigned long long unhex(const char *cp)
{
    unsigned long long ull = 0;
    for(;;){
        char c = *cp++;
        if(!( (c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f') )) break;
        ull = (ull<<4) | (c - (c >= 'a' ? 'a'-10 : c >= 'A' ? 'A'-10 : '0'));
    }
    return ull;
}

unsigned char deswappify(char **proclist)
{
	long pagesize = sysconf(_SC_PAGESIZE);
	unsigned long kbytes = 0, total = 0;
	size_t start_addr, end_addr;
	char buf[bufsize * 1024];
	char sLine[200];
	char addr_buf[32];
	char kbytes_buf[32];
	char matched = 0;
	char last = 0;
	char path[50] = "/proc/";

	if (isatty(fileno(stdout))) // only flush output on new line when redirected to file
		setbuf(stdout, NULL);

	for (int i = 0; proclist[i] != NULL; i++)
	{
		int pid_length = strlen(proclist[i]);
		memcpy(&path[6], proclist[i], pid_length + 1);
		memcpy(&path[6 + pid_length], "/smaps", 6 + pid_length + 1);
		FILE *fp = fopen(path , "r");
		if (!fp)
		{
			if (quiet < 2) fprintf(stderr, "failed to open %s\n", path);
			continue;
		}

		char addr_line = 0;
		while (fgets(sLine, sizeof(sLine), fp) != NULL)
		{
			int iii = 0;
			int ii = 0;
			for (; ii < sizeof(sLine); ++ii)
			{
				if ((sLine[0] >= '0' && sLine[0] <= '9') || (sLine[0] >= 'a' && sLine[0] <= 'f'))
				{
					for (; ii < sizeof(sLine); ++ii)
					{
						if (ii > 7 && sLine[ii] == '-') // assume memory address length is at least 8 (hex string)
						{
							addr_line = 1;
							memset(addr_buf, 0, sizeof(addr_buf));
							strncpy(addr_buf, &sLine[0], ii);
							start_addr = unhex(addr_buf);
							iii = ii;
							for (; ii < sizeof(sLine); ++ii)
							{
								if (sLine[ii] == ' ')
								{
									if (--ii - iii != iii) // end_addr should have the same length as start_addr
									{
										ii = sizeof(sLine);
										break;
									}
									memset(addr_buf, 0, sizeof(addr_buf));
									strncpy(addr_buf, &sLine[++iii], ii - iii);
									end_addr = unhex(addr_buf);
									ii = sizeof(sLine);
								}
							}
							break;
						}
					}
					break;
				}
				else if (ii == 0 && addr_line == 1 && sLine[0] == 'S' && sLine[3] == 'p') // look for Swap
				{
					for (++ii; ii < sizeof(sLine); ++ii)
					{
						if (sLine[ii] == 0)
							break;
						if (sLine[ii] >= '1' && sLine[ii] <= '9') // skip starting with 0, which means nothing is swapped
						{
							iii = ii;
							for (; ii < sizeof(sLine); ++ii)
							{
								if (sLine[ii] == ' ' && sLine[ii + 1] == 'k')
								{
									memset(kbytes_buf, 0, sizeof(kbytes_buf));
									strncpy(kbytes_buf, &sLine[iii], ii - iii);
									kbytes = atoi(kbytes_buf);
									if (kbytes == 0)
										break;
									memcpy(&path[6], proclist[i], pid_length + 1);
									memcpy(&path[6 + pid_length], "/mem\0", 6 + pid_length + 1);
									int fd = open(path, O_RDONLY);
									if (!fd)
									{
										if (quiet < 2) fprintf(stderr, "failed to open %s\n", path);
										break;
									}
									if (!last)
									{
										memcpy(&path[6], proclist[i], pid_length + 1);
										memcpy(&path[6 + pid_length], "/comm\0", 6 + pid_length + 1);
										FILE *fd = fopen(path, "r");
										char procname[16] = {};
										int len;
										if (fd)
										{
											if (fgets(procname, sizeof(procname), fd) == NULL)
												strcpy(procname, "unknown");
											len = strlen(procname);
											if (procname[len - 1] == '\n')
												procname[len - 1] = '\0';
											fclose(fd);
										}
										if (quiet < 1) printf("Deswappifying PID %s (%s)", proclist[i], procname);
										last = 1;
									}
									else
									{
										printf(".");
									}
									if (!matched)
										matched = 1;
									lseek(fd, start_addr, SEEK_SET);
									int returnv;
									for (; start_addr < end_addr; start_addr += (bufsize * 1024))
										if (!(returnv = read(fd, buf, bufsize * 1024)))
										{
											if (quiet < 2) fprintf(stderr, "error reading addr 0x%lx from %s\n", start_addr, path);
											close(fd);
											break;
										}
										for (start_addr -= end_addr; start_addr = 0; start_addr - pagesize)
											returnv = read(fd, buf, pagesize);

									close(fd);
									total += kbytes;
									ii = sizeof(sLine);
									break;
								}
							}
						}
					}
					addr_line = 0;
				}
				else
					break;
			}
		}
		fclose(fp);
		if (matched)
		{
			printf("\n");
			last = 0;
			matched = 0;
		}
	}
	if (quiet < 1) printf("Total deswappified: %ld kB\n", total);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 1)
		displayhelp(argv);

	char **proclist = NULL;
	FILE *fp = fopen("/proc/sys/kernel/pid_max" , "r");
	if (fp)
	{
		char str[10] = {};
		if(!(fgets(str, 10, fp)))
		{
			if (quiet < 2) fprintf(stderr, "error opening /proc/sys/kernel/pid_max!\n");
			return 1;
		}
		max_pid = atoi(str);
		fclose(fp);
	}

 	if (!(proclist = parsearg(argc, argv, proclist)))
	{
		fprintf(stderr, "Cannot allocate memory.\n");
		exit(1);
	}

	deswappify(proclist);

	for (int i = 0; proclist[i] != NULL; ++i)
		free(proclist[i]);
	free(proclist);

	return 0;
}