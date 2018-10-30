#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <regex.h>

#define PAGESIZE 4096

int displayhelp(char **argv)
{
	printf("Usage: \n %s [options]\n\n", argv[0]);
	printf(
		"Basic options:\n"
		" -a\t\t\tall processes\n"
		" -p\t\t\tone or more PIDs seperated by space\n");
	return -1;
}

int processall(char **proclist)
{
	DIR *d = NULL;
	struct dirent *ent;
	char dirname[] = "/proc/";
	int i = 0;
	if (!(d = opendir(dirname)))
	{
		fprintf(stderr, "error opening /proc directory\n");
		return 1;
	}

	while ((ent = readdir(d)) != NULL)
	{
		if (ent->d_type == DT_DIR && ent->d_name[0] >= '0' && ent->d_name[0] <= '9')
		{
			proclist[i] = ent->d_name;
			//printf("%s\n", proclist[i]);
			++i;
		}
	}
	proclist[i] = 0;
}

int parsearg(int argc, char **argv, char **proclist)
{
	int help = 0;
	int i = 1;

	for(; i < argc; ++i)
	{
		const char * thisargv = argv[i];
		if(thisargv[0] == '-')
		{
			int np = ++i;
			if(np > argc)
			{
				help = 1;
				break;
			}
			const char * nextargv = argv[np];
			switch(thisargv[1])
			{
			case 'a':
				if (argc == 2 && thisargv[2] == '\0')
					processall(proclist);
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
					for (; np < argc && *argv[np] != '-'; ++np)
					{
						// only allow digits for PID
						for (int i = 0; argv[np][i] != '\0'; ++i)
						{
							if (argv[np][i] < '0' || argv[np][i] > '9')
							{
								help = 1;
								break;
							}
						}
						proclist[ii] = argv[np];
						i++;
						ii++;
					}
					proclist[ii] = 0;
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
	char buf[PAGESIZE];
	size_t start_addr, end_addr;
	regex_t regex, regex2;
	regmatch_t groupArray[3];
	unsigned int bytes = 0, total = 0;

	if (regcomp(&regex, "^([0-9a-f]+)-([0-9a-f]+)", REG_EXTENDED))
	{
		fprintf(stderr, "Could not compile regular expression.\n");
		return 1;
	};
	if (regcomp(&regex2, "^Swap:\\s*([0-9]+) *kB", REG_EXTENDED))
	{
		fprintf(stderr, "Could not compile regular expression.\n");
		return 1;
	};
	char sLine[1024];
	char addr_buf[32];
	char bytes_buf[100];
	char matched = 0;
	char *last = 0;
	setbuf(stdout, NULL);
	for (unsigned int i = 0; proclist[i] != NULL; ++i)
	{
		char path[1024] = "/proc/";
		strcat(path, proclist[i]);
		strcat(path, "/smaps");
		FILE *fp = fopen(path , "r");
		if (!fp)
		{
			fprintf(stderr, "failed to open %s\n", path);
			continue;
		}
		while(fgets(sLine, 1024, fp))
		{
			if (regexec(&regex, sLine, 3, groupArray, 0) == 0)
			{
				memset(addr_buf, 0, sizeof(addr_buf));
				strncpy(addr_buf, &sLine[groupArray[1].rm_so], groupArray[1].rm_eo - groupArray[1].rm_so);
				start_addr = unhex(addr_buf);

				memset(addr_buf, 0, sizeof(addr_buf));
				strncpy(addr_buf, &sLine[groupArray[2].rm_so], groupArray[2].rm_eo - groupArray[2].rm_so);
				end_addr = unhex(addr_buf);
			}
			else if (regexec(&regex2, sLine, 2, groupArray, 0) == 0)
			{
				memset(bytes_buf, 0, sizeof(bytes_buf));
				strncpy(bytes_buf, &sLine[groupArray[1].rm_so], groupArray[1].rm_eo - groupArray[1].rm_so);
				bytes = atoi(bytes_buf);
				if (bytes == 0)
					continue;
				char path[30] = "/proc/";
				strcat(path, &*proclist[i]);
				strcat(path, "/mem");
				int fd = open(path, O_RDONLY);
				if (!fd)
				{
					fprintf(stderr, "failed to open %s\n", path);
					break;
				}
				if (!last)
				{
					printf("Deswappifying PID %s.", &*proclist[i]);
					last = &*proclist[i];
				}
				else
				{
					printf(".");
				}
				if (!matched)
					matched = 1;
				lseek(fd, start_addr, SEEK_SET);
				int returnv;
				for (; start_addr < end_addr; start_addr += PAGESIZE)
					if (!(returnv = read(fd, buf, sizeof(buf))))
					{
						fprintf(stderr, "error reading addr 0x%lx from %s\n", start_addr, path);
						close(fd);
						break;
					}
				close(fd);
				total += bytes;
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
	regfree(&regex);
	regfree(&regex2);
	printf("Total deswappified: %d kB\n", total);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 1)
	{
		displayhelp(argv);
		return -1;
	}
	char str[10] = {};
	FILE *fp = fopen("/proc/sys/kernel/pid_max" , "r");
	if (fp)
	{
		if(!(fgets(str, 10, fp)))
		{
			fprintf(stderr, "error opening /proc/sys/kernel/pid_max!\n");
			return 1;
		}
		fclose(fp);
	}

	char *proclist[argc == 2 ? atoi(str) + 1 : argc - 1];
	if (parsearg(argc, argv, proclist) == -1)
		return -1;

	deswappify(proclist);

	return 0;
}