/*
    sockrund - daemon to run processes and create UNIX sockets to be able to 
        monitor the process statuses with external utilities/daemons

Copyright (c) 2014, Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

/* If you have any question, I'll recommend you to ask irc.freenode.net#openrc */

/* === includes === */

#include <stdio.h>	/* fprintf()		*/
#include <stdlib.h>	/* atservice_exit()	*/
#include <string.h>	/* strerror()		*/
#include <pthread.h>	/* pthread_create()	*/
#include <unistd.h>	/* execve()		*/
#include <errno.h>	/* errno		*/
#include <sys/stat.h>	/* mkdir()		*/
#include <sys/types.h>	/* mkdir()		*/
#include <sys/socket.h>	/* socket()		*/
#include <sys/un.h>	/* struct sockaddr_un	*/
#include <sys/wait.h>	/* waitpid()		*/
#include <sys/ptrace.h>	/* ptrace()		*/
#include <search.h>	/* hsearch()		*/

/* === configuration === */

#define SVC_MYNAME	"sockrund"
#define DIR_SOCKETS	"/run/openrc/sockrund"
//#define ENV_SVCNAME	"RC_SVCNAME"
#define SOCKET_BACKLOG	5
#define PATH_CTRLSOCK	DIR_SOCKETS"/"SVC_MYNAME
#define MAX_COMMANDERS	16
#define MAX_SERVICES	(1<<16)
#define MAX_SERVICENAME_LENGTH (1<<6)

/* === portability hacks === */

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* === enums === */

typedef enum {
	SS_FREE = 0,
	SS_NEW,
	SS_RUNNED,
	SS_EXIT,
} svcstatus_t;

/* === structs === */

typedef struct {
	int		id;
	svcstatus_t	status;
	char		name[MAX_SERVICENAME_LENGTH];
	pid_t		pid;
	pthread_t	thread;
} service_t;

/* === global variables === */

int ctrlsock        = 0;
int commander_count = 0;
int svc_count       = 0;
int svc_nextnum     = 0;
static service_t svcs[MAX_SERVICES] = {{0}};
pthread_mutex_t hsearch_mutex = PTHREAD_MUTEX_INITIALIZER;

/* === code self === */

/* - hsearch - */

static inline ENTRY *hsearch_safe(ENTRY search_req, ACTION action) {
	ENTRY *search_res_p;

	pthread_mutex_lock(&hsearch_mutex);
	search_res_p = hsearch(search_req, action);
	pthread_mutex_unlock(&hsearch_mutex);

	return search_res_p;
}

/* - sock - */

int sock_prepare(const char const *path) {
	int sock;
	size_t sock_addr_len;
	struct sockaddr_un	sock_addr	= {0};

	sock_addr.sun_family = AF_UNIX;
	strcpy(sock_addr.sun_path, path);	/* TODO: check path length */

	sock_addr_len = sizeof(sock_addr.sun_family) + strlen(sock_addr.sun_path);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return -1;

	unlink(path);

	if (bind(sock, (struct sockaddr *)&sock_addr, sock_addr_len))
		return -1;

	if (listen(sock, SOCKET_BACKLOG))
		return -1;

	return sock;
}

/* - service - */

service_t *service_new(char *svc_name, const pid_t svc_pid) {
	service_t *svc;
	int svc_nextnum_old;
	int svc_id;
	ENTRY item;

	svc_nextnum_old = svc_nextnum;

	while (svcs[svc_nextnum++].status != SS_FREE) {
		if (svcs[svc_nextnum-1].status == SS_EXIT) {
			/* cleanup */

			void *exitcode;
			int svc_id;
			service_t *svc;
			ENTRY item;

			svc_id = svc_nextnum-1;
			svc = &svcs[svc_id];

			item.key  = svc->name;
			item.data = NULL;
			hsearch_safe(item, ENTER);
			pthread_join(svcs[svc_id].thread, &exitcode);

			memset(svc, 0, sizeof(*svc));
			break;
		}

		if (svc_nextnum >= MAX_SERVICES)
			svc_nextnum = 0;

		if (svc_nextnum == svc_nextnum_old)
			return NULL;
	}

	svc_id = svc_nextnum-1;

	svc = &svcs[svc_id];
	svc->id     = svc_id;
	svc->status = SS_NEW;
	svc->pid    = svc_pid;

	svc_name[MAX_SERVICENAME_LENGTH] = 0;
	strcpy(svc->name, svc_name);

	item.key  = svc->name;
	item.data = svc;
	hsearch_safe(item, ENTER);

	return svc;
}

int service_limpet(service_t *svc) {
	pthread_t		sock_ctrl_th	=  0;
	int			sock		=  0;
	char			sock_path[PATH_MAX];

	sprintf(sock_path, DIR_SOCKETS"/%s", svc->name);	/* TODO: check svc->name length */

	#define service_exit(exitcode) { service_cleanup(); svc->status = SS_EXIT; return exitcode; }
	inline void service_cleanup()
	{
		if (sock) {
			close(sock);
			unlink(sock_path);
			sock = 0;
		}

		return;
	}

	void *sock_ctrl(void *arg)
	{
		while (sock) {
			int events;
			int client;
			fd_set rfds;

			FD_ZERO(&rfds);
			FD_SET(sock, &rfds);
			events = select(sock+1, &rfds, NULL, NULL, NULL);

			if (events < 0)
				break;

			if (!events)
				continue;

			client = accept(sock, NULL, NULL);
			close(client);
		}

		return NULL;
	}

	{ /* preparing the socket */
		sock = sock_prepare(sock_path);
		if(sock == -1) {
			fprintf(stderr, "Cannot create/listen an UNIX socket by path \"%s\": %s.\n", sock_path, strerror(errno));
			service_exit(errno);
		}
	}

	{ /* running a thread to accept and drop clients */
		if (pthread_create(&sock_ctrl_th, NULL, sock_ctrl, NULL)) {
			fprintf(stderr, "Cannot create a thread to control the socket: %s.\n", strerror(errno));
			service_exit(errno);
		}
	}

	{ /* running the process */
		int child_status;

		ptrace(PTRACE_SYSCALL, svc->pid, 0, 0);

		waitpid(svc->pid, &child_status, 0);
		printf("test\n");
		service_exit(WEXITSTATUS(child_status));
		printf("test2\n");
	}

	service_exit(EXIT_FAILURE);	/* this's unreachable line */
}

int service_attach(char *svc_name, const pid_t svc_pid) {
	service_t *svc = service_new(svc_name, svc_pid);
	if (svc == NULL)
		return -1;

	return pthread_create(&svc->thread, NULL, (void *(*)(void *))service_limpet, svc);
}

int service_run(char *svc_name, char *argv[]) {
	pid_t svc_pid;

	{ /* running the process */
		svc_pid = fork();

		if (svc_pid == -1) {
			return errno;
		}

		if (svc_pid == 0) { /* the child */
			ptrace(PTRACE_TRACEME, 0, 0, 0);	/* waiting while ptrace()-ing started */
			argv++;
			execvp(argv[0], argv);
			exit(EXIT_FAILURE);			/* exec never returns :) */
		}
	}

	service_t *svc = service_new(svc_name, svc_pid);
	if (svc == NULL)
		return -1;

	return pthread_create(&svc->thread, NULL, (void *(*)(void *))service_limpet, svc);
}

service_t *service_byname(char *svc_name) {
	ENTRY *search_res_p, search_req = {svc_name, NULL};

	search_res_p = hsearch_safe(search_req, FIND);

	if (search_res_p == NULL)
		return NULL;

	return search_res_p->data;
}

int service_finish(service_t *svc) {
	return kill(svc->pid, SIGTERM);
}

int service_down(char *svc_name) {
	service_t *svc = service_byname(svc_name);

	if (svc == NULL)
		return EINVAL;

	return service_finish(svc);
}

/* - main - */

void cleanup() {
	if (ctrlsock) {
		close(ctrlsock);
		unlink(PATH_CTRLSOCK);
		ctrlsock = 0;
	}

	return;
}

void main_term(int sig) {
	exit(0);
}

void *commander_ctrl(void *sock_p) {
	char cmd[BUFSIZ+2], *ptr;
	int sock = *(int *)sock_p;

	while (sock) {
		int events;
		fd_set rfds;
		size_t rbytes;

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		events = select(sock+1, &rfds, NULL, NULL, NULL);

		if (events < 0)
			break;

		if (!events)
			continue;

		rbytes = read(sock, cmd, BUFSIZ+1);

		if (rbytes <= 0)	/* got error, or connection closed */
			break;

		if (rbytes >= BUFSIZ+1) /* too long command */
			break;

		cmd[rbytes] = 0;

		ptr = &cmd[1];
		switch(*cmd) {
			case 'a': {	/* supervise new service, attaching by pid */
				char *svc_name;
				int ret;
				pid_t svc_pid;
				if(sscanf(ptr, "%u", &svc_pid) < 1)
					continue;

				while(*(ptr++) > 0x20);

				svc_name = ptr;
				if ((ret = service_attach(svc_name, svc_pid)))
					dprintf(sock, "Error: %i\n", ret);
				break;
			}
			case 'd': {	/* deattach/delete/down a service */
				char *svc_name;
				int ret;

				svc_name = ptr;
				if ((ret = service_down(svc_name)))
					dprintf(sock, "Error: %i\n", ret);
			}
			default:	/* unknown command */
				fprintf(stderr, "Unknown command: %s\n", cmd);
				break;
		}

	}

	close(sock);
	*(int *)sock_p = 0;
	return NULL;
}

int main(int argc, char *argv[]) {
	{ /* initializating cleanup function */
		if (atexit(cleanup)) {
			fprintf(stderr, "Got error while atexit(): %s.\n", strerror(errno));
			exit(errno);
		}
		signal(SIGTERM,	main_term);
		signal(SIGABRT,	main_term);
		signal(SIGINT,	main_term);
		signal(SIGQUIT,	main_term);
	}

	{ /* checking and preparing some stuff */
		if (mkdir(DIR_SOCKETS, 0700)) {
			if (errno != EEXIST) {
				fprintf(stderr, "Cannot create directory \""DIR_SOCKETS"\": %s.\n", strerror(errno));
				exit(errno);
			}
		}

		hcreate(MAX_SERVICES*2);
	}

	{ /* preparing the socket */
		ctrlsock = sock_prepare(PATH_CTRLSOCK);
		if(ctrlsock == -1) {
			fprintf(stderr, "Cannot create/listen an UNIX socket by path \""PATH_CTRLSOCK"\": %s.\n", strerror(errno));
			exit(errno);
		}
	}

	while (ctrlsock) { /* the "infinite" loop */
		int i;
		int events;
		int commander;
		fd_set rfds;
		pthread_t commander_th[MAX_COMMANDERS] = {0};

		FD_ZERO(&rfds);
		FD_SET(ctrlsock, &rfds);
		events = select(ctrlsock+1, &rfds, NULL, NULL, NULL);

		if (events < 0)
			break;

		if (!events)
			continue;

		i=0;
		while (i < commander_count) {
			if (!commander_th[i] || (pthread_kill(commander_th[i], 0) == ESRCH)) {
				void *ret;
				pthread_join(commander_th[i], &ret);
				memcpy(&commander_th[i], &commander_th[--commander_count], sizeof(*commander_th));
			}
			i++;
		}

		commander = accept(ctrlsock, NULL, NULL);
		if (commander_count >= MAX_COMMANDERS) {
			close(commander);
			continue;
		}

		if (pthread_create(&commander_th[commander_count++], NULL, commander_ctrl, &commander)) {
			fprintf(stderr, "Cannot create a thread to control the cmd-socket: %s.\n", strerror(errno));
			exit(errno);
		}
	}

	hdestroy();
	exit(0);
}

