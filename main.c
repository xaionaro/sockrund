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
#include <syslog.h>	/* syslog()		*/
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
#define MAX_SERVICES	(1<<12)
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
	int		sock;
	pthread_t	sock_thread;
} service_t;

/* === global variables === */

int verbosity       = LOG_DEBUG;
int ctrlsock        = 0;
int commander_count = 0;
int svc_count       = 0;
int svc_nextnum     = 0;
int sockdir_fd      = 0;
static service_t svcs[MAX_SERVICES] = {{0}};
void *tsearch_pid2svc_bt = NULL;
pthread_mutex_t tsearch_pid2svc_mutex	= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t hsearch_mutex		= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ptrace_mutex		= PTHREAD_MUTEX_INITIALIZER;

/* === code self === */

/* - macro - */

#define   likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

/* - log - */

#define log(level, ...) if (unlikely(level <= verbosity)) fprintf(stderr, __VA_ARGS__);
//syslog(level,  __VA_ARGS__)

/* - ptrace - */

#define ptrace_svc(request, svc, ...) {\
	errno=0;\
	if (unlikely(ptrace(request, svc->pid, ## __VA_ARGS__) == -1))\
		if (likely(errno)) {\
			log(LOG_EMERG, "Got error while ptrace(%i, %i, ...): %s.\n", request, svc->pid, strerror(errno));\
			return service_exit(svc, errno);\
		}\
}

int ptrace_ctrl(void *arg)
{
#if 0
	while (1) {
		siginfo_t winfo;

		if (!svc_count) { /* if there're no children */
			/* wait until ptrace_mutex will be unlocked */
			pthread_mutex_lock(&ptrace_mutex);
			pthread_mutex_unlock(&ptrace_mutex);
		}

		if (waitid(P_ALL, 0, &winfo, WSTOPPED) == -1) {
			if (errno == ECHILD) {
				log(LOG_DEBUG, "There're no children, but waitid() was been called.\n");
				svc_count = 0;
				continue;
			}

			log(LOG_EMERG, "Got error while waitid(): %s. Exit.\n", strerror(errno));
			exit(errno);
		}

		log(LOG_DEBUG, "iteration 3\n");
		if (winfo.si_status >> 16 == PTRACE_EVENT_FORK) {
			int newpid;
			log(LOG_DEBUG, "sdf\n");
			ptrace_svc(PTRACE_GETEVENTMSG, winfo.si_pid, NULL, (long)&newpid);
			log(LOG_DEBUG, "ddff\n");
			ptrace_svc(PTRACE_DETACH, newpid, NULL, NULL);
			log(LOG_DEBUG, "Attached to offspring %d\n", newpid);  
		} else
		if (winfo.si_status >> 16 == PTRACE_EVENT_FORK)
			log(LOG_DEBUG, "Child exited: %d\n", winfo.si_pid);

		ptrace_svc(PTRACE_CONT, winfo.si_pid, NULL, WSTOPSIG(winfo.si_status));
	}
#endif
	return 0;
}

/* - hsearch - */

static inline ENTRY *hsearch_safe(ENTRY search_req, ACTION action)
{
	ENTRY *search_res_p;

	pthread_mutex_lock(&hsearch_mutex);
	search_res_p = hsearch(search_req, action);
	pthread_mutex_unlock(&hsearch_mutex);

	return search_res_p;
}

/* - sock - */

int sock_prepare(const char const *path)
{
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

void *sock_ctrl(service_t *svc)
{
	log(LOG_DEBUG, "sock_ctrl(): %i\n", svc->sock);
	while (svc->sock) {
		int events;
		int client;
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(svc->sock, &rfds);
		events = select(svc->sock+1, &rfds, NULL, NULL, NULL);

		if (events < 0)
			break;

		if (!events)
			continue;

		client = accept(svc->sock, NULL, NULL);
		close(client);
	}

	return NULL;
}

/* - service - */

static inline void service_cleanup(service_t *svc)
{
	if (svc->sock) {
		close(svc->sock);
		unlink(svc->name);
		svc->sock = 0;
	}

	return;
}

static inline int service_exit(service_t *svc, int exitcode)
{
	switch (svc->status) {
		case SS_FREE:
		case SS_EXIT:
			break;
		default:
			service_cleanup(svc);
			svc->status = SS_EXIT;
			log(LOG_DEBUG, "%i exit: %s\n", svc->pid, strerror(exitcode));
			svc_count--;
	}
	return exitcode;
}

service_t *service_new(char *svc_name, const pid_t svc_pid)
{
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
			ENTRY item_name2svc; //, item_pid2svc;

			svc_id = svc_nextnum-1;
			svc = &svcs[svc_id];
/*
			item_pid2svc.key  = (void *)(long)svc_pid;
			item_pid2svc.data = NULL;
			tdelete(&item_pid2svc, &tsearch_pid2svc_bt, );
*/
			item_name2svc.key  = svc->name;
			item_name2svc.data = NULL;
			hsearch_safe(item_name2svc, ENTER);
			pthread_join(svcs[svc_id].sock_thread, &exitcode);

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

	svc_count++;
	return svc;
}

int service_attach(char *svc_name, const pid_t svc_pid) {
	service_t 	*svc 		= service_new(svc_name, svc_pid);

	if (svc == NULL)
		return -1;

	{ /* preparing the socket */
		svc->sock       = sock_prepare(svc->name);
		if (svc->sock == -1) {
			log(LOG_ALERT, "Cannot create/listen an UNIX socket by path \"%s\" (the last chdir() was to \""DIR_SOCKETS"\"): %s.\n", svc->name, strerror(errno));
			return service_exit(svc, errno);
		}
	}

	{ /* running a thread to accept and drop clients */
		if (pthread_create(&svc->sock_thread, NULL, (void *(*)(void *))sock_ctrl, svc)) {
			log(LOG_ALERT, "Cannot create a thread to control the socket: %s.\n", strerror(errno));
			return service_exit(svc, errno);
		}
	}

	{ /* clinging to the process */
		int child_status;

		/* setting up catching of forks and exits */

		log(LOG_DEBUG, "attaching to %d\n", svc->pid);
		ptrace_svc(PTRACE_ATTACH, svc);
		if (waitpid(svc->pid, &child_status, 0) == -1 && errno)
			return service_exit(svc, errno);
		ptrace_svc(PTRACE_SETOPTIONS, svc, NULL, PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXIT);

		/* unhalting the process */

		ptrace_svc(PTRACE_CONT, svc, NULL, WSTOPSIG(child_status));

		/* now the process is monitored by ptrace_ctrl() thread, so unlocking it (if it's locked) */
		pthread_mutex_unlock(&ptrace_mutex);
	}

	return 0;
}

int service_run(char *svc_name, char *argv[]) {
	pid_t svc_pid;

	{ /* running the process */
		svc_pid = fork();

		if (svc_pid == -1)
			return errno;

		if (svc_pid == 0) { /* the child */
			ptrace(PTRACE_TRACEME, 0, 0, 0);	/* waiting while ptrace()-ing started */
			argv++;
			execvp(argv[0], argv);
			return errno;				/* exec*() never returns on success :) */
		}
	}

	return service_attach(svc_name, svc_pid);
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
	if (likely(ctrlsock)) {
		close(ctrlsock);
		unlink(PATH_CTRLSOCK);
		ctrlsock = 0;
	}

	return;
}

void main_term(int sig) {
	exit(0);

	return;
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
				log(LOG_NOTICE, "Unknown command: %s\n", cmd);
				break;
		}

	}

	close(sock);
	*(int *)sock_p = 0;
	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_t ptrace_ctrl_thread = 0;

	{ /* initializating cleanup function */
		if (atexit(cleanup)) {
			log(LOG_EMERG, "Got error while atexit(): %s.\n", strerror(errno));
			exit(errno);
		}
		signal(SIGTERM,	main_term);
		signal(SIGABRT,	main_term);
		signal(SIGINT,	main_term);
		signal(SIGQUIT,	main_term);
	}

	{ /* checking and preparing some stuff */
		openlog(NULL, LOG_PID|LOG_CONS|LOG_NDELAY, LOG_DAEMON);

		if (mkdir(DIR_SOCKETS, 0700)) {
			if (errno != EEXIST) {
				log(LOG_EMERG, "Cannot create directory \""DIR_SOCKETS"\": %s.\n", strerror(errno));
				exit(errno);
			}
		}

		if (chdir(DIR_SOCKETS) == -1) {
			log(LOG_EMERG, "Cannot open() directory \""DIR_SOCKETS"\": %s.\n", strerror(errno));
			exit(errno);
		}

		hcreate(MAX_SERVICES*2);
	}

	{ /* running the monitoring thread */
		pthread_mutex_lock(&ptrace_mutex);	/* hold on ptrace_ctrl until any child appear */

		if (pthread_create(&ptrace_ctrl_thread, NULL, (void *(*)(void *))ptrace_ctrl, NULL)) {
			log(LOG_EMERG, "pthread_create() error: %s.\n", strerror(errno));
			exit(errno);
		}
	}

	{ /* preparing the socket */
		ctrlsock = sock_prepare(PATH_CTRLSOCK);
		if (ctrlsock == -1) {
			log(LOG_EMERG, "Cannot create/listen an UNIX socket by path \""PATH_CTRLSOCK"\": %s.\n", strerror(errno));
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

		if (unlikely(pthread_create(&commander_th[commander_count++], NULL, commander_ctrl, &commander))) {
			log(LOG_EMERG, "Cannot create a thread to control the cmd-socket: %s.\n", strerror(errno));
			exit(errno);
		}
	}

	hdestroy();
	closelog();
	exit(0);
}

