#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <regex.h>

#define PAGESIZE 4096

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
	  printf("Could not compile regular expression.\n");
	  return 1;
	};
	if (regcomp(&regex2, "^Swap:\\s*([0-9]+) *kB", REG_EXTENDED))
	{
	  printf("Could not compile regular expression.\n");
	  return 1;
	};
	char sLine[1024];
	char addr_buf[32];
	char bytes_buf[100];

	for (unsigned int i = 0; proclist[i] != NULL; ++i)
	{
		char path[1024] = "/proc/";
//		printf("%s\n", proclist[i]);
		strcat(path, proclist[i]);
		strcat(path, "/smaps");
		FILE *fp = fopen(path , "r");
		if (!fp)
		{
			printf("failed to open %s\n", path);
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
					printf("failed to open %s\n", path);
					break;
				}
				printf("Deswappifying %s (0x%lx-0x%lx)...\n", &*proclist[i], start_addr, end_addr);
				lseek(fd, start_addr, SEEK_SET);
				int returnv;
				for (; start_addr < end_addr; start_addr += PAGESIZE)
					if (!(returnv = read(fd, buf, sizeof(buf))))
					{
						printf("error reading addr 0x%lx from %s\n", start_addr, path);
						close(fd);
						break;
					}
				close(fd);
				total += bytes;
			}
		}
		fclose(fp);
	}
	regfree(&regex);
	regfree(&regex2);
	printf("Total deswappified: %d kB\n", total);
	return 0;
}

int main(int argc, char **argv)
{
	char str[10] = {};

	if (argc == 1)
	{
		FILE *fp = fopen("/proc/sys/kernel/pid_max" , "r");
		if (fp)
		{
			if(!(fgets(str, 10, fp)))
			{
				printf("error opening /proc/sys/kernel/pid_max!\n");
				return 1;
			}
			fclose(fp);
		}
	}

	char *proclist[argc == 1 ? atoi(str) + 1 : argc - 1];

	if (argc == 1)
	{
		DIR *d = NULL;
		struct dirent *ent;
		char dirname[] = "/proc/";
		if (!(d = opendir(dirname)))
		{
			printf("error opening /proc directory\n");
			return 1;
		}

		int i = 0;
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
	else
	{
		unsigned char i = 0;
		for (; i < argc - 1; i++)
			proclist[i] = argv[i + 1];
		proclist[i] = 0;
	}
	deswappify(proclist);

	return 0;
}