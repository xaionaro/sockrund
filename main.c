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

#define SVC_MYNAME			"sockrund"
#define DIR_SOCKETS			"/run/openrc/sockrund"
//#define ENV_SVCNAME			"RC_SVCNAME"
#define SOCKET_BACKLOG			5
#define PATH_CTRLSOCK			DIR_SOCKETS"/"SVC_MYNAME
#define MAX_COMMANDERS			16
#define MAX_SERVICES			(1<<10)
#define MAX_SERVICENAME_LENGTH 		(1<<6)
#define MAX_WATCHEDPIDS			(1<<16)
#define MAX_WATCHEDPIDS_PERSERVICE	(1<<5)
#define INTERVAL_CLEANUP		60

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
	pid_t		pid[MAX_WATCHEDPIDS_PERSERVICE];
	int		pid_count;
	int		sock;
	pthread_t	sock_thread;
} service_t;

typedef struct {
	pid_t		pid;
	service_t	*svc;
} pidsvc_t;

/* === global variables === */

int time_lastcleanup = 0;
int verbosity        = LOG_DEBUG;
int ctrlsock         = 0;
int commander_count  = 0;
int svc_count        = 0;
int svc_nextnum      = 0;
int sockdir_fd       = 0;
int pid_count        = 0;
int pid_nextnum      = 0;
pid_t ptrace_arg_attachservice_pid      = 0;
service_t *ptrace_arg_attachservice_svc = NULL;
service_t *ptrace_arg_detachservice = NULL;
pthread_t ptrace_ctrl_thread = 0;
static service_t svcs[MAX_SERVICES] = {{0}};
void *tsearch_pid2svc_bt = NULL;
pthread_mutex_t tsearch_pid2svc_mutex	= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t hsearch_mutex		= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ptrace_mutex		= PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ptrace_send_mutex	= PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  ptrace_mutex_cond	= PTHREAD_COND_INITIALIZER;
pidsvc_t item_pid2svc[MAX_WATCHEDPIDS]	= {{0}};

/* === protos === */

extern service_t *service_bypid(pid_t svc_pid);
extern int service_exit(service_t *svc, int exitcode);

/* === code self === */

/* - macro - */

#define   likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
#define PTRACE_EVENT(proc_status) ((proc_status) >> 16)

/* - log - */

#define log(level, ...) if (unlikely(level <= verbosity)) fprintf(stderr, __VA_ARGS__);
//syslog(level,  __VA_ARGS__)

/* - compar - */

int compar_pidsvc_pid(const void *a, const void *b)
{
//	log(LOG_DEBUG, "cmp: %d %d\n", ((pidsvc_t *)a)->pid, ((pidsvc_t *)b)->pid);
	return ((pidsvc_t *)a)->pid - ((pidsvc_t *)b)->pid;
}

/* - pid - */

int pid_register(pid_t pid, service_t *svc) {
	pidsvc_t *item_pid2svc_p;
#ifdef PARANOID
	int pid_nextnum_old;
#endif

	if (pid_count >= MAX_WATCHEDPIDS) {
		log(LOG_ALERT, "There's no more space left to store information about PIDs (#0).\n");
		return ENOMEM;
	}

	if (svc->pid_count >= MAX_WATCHEDPIDS_PERSERVICE) {
		log(LOG_ALERT, "There's no more space left to store information about PIDs of service \"%s\".\n", svc->name);
		return ENOMEM;
	}

#ifdef PARANOID
	pid_nextnum_old = pid_nextnum;
#endif
	while (item_pid2svc[pid_nextnum].pid) {
		pid_nextnum++;

		if (pid_nextnum >= MAX_WATCHEDPIDS)
			pid_nextnum = 0;
#ifdef PARANOID
		if (pid_nextnum == pid_nextnum_old) {
			log(LOG_ALERT, "There's no more space left to store information about PIDs (#1).\n");
			return ENOMEM;
		}
#endif
	}

	{ /* storing the record about pid into binary tree */
		char *res;
		item_pid2svc_p = &item_pid2svc[pid_nextnum];
		item_pid2svc_p->pid  = pid;
		item_pid2svc_p->svc  = svc;

		res = tsearch(item_pid2svc_p, &tsearch_pid2svc_bt, compar_pidsvc_pid);

		if (*(void **)res != item_pid2svc_p) { /* that means the record was already exists */
			log(LOG_NOTICE, "The record for pid %d is already exist (the error appeared while working on \"%s\").\n", pid, svc->name);
			memset(item_pid2svc_p, 0, sizeof(*item_pid2svc_p));
			return EEXIST;
		}
	}

	log(LOG_DEBUG, "Registered a new pid: %d -> %s (%d).\n", pid, svc->name, svc->pid_count);
	svc->pid[svc->pid_count++] = pid;

	pid_count++;
	return 0;
}

int pid_unregister(pid_t pid, service_t *svc) {
	void *res;
	int i;
	pidsvc_t item_pid2svc, *item_pid2svc_res_p;

	item_pid2svc.pid  = pid;

	res = tfind(&item_pid2svc, &tsearch_pid2svc_bt, compar_pidsvc_pid); /* TODO: remove double-searching through the BT */
	if (res == NULL) {
		log(LOG_NOTICE, "Cannot find pid %d in internal list. (#0)\n", pid);
		return ESRCH;
	}

	item_pid2svc_res_p = *(void **)res;
	tdelete(&item_pid2svc, &tsearch_pid2svc_bt, compar_pidsvc_pid);

	memset(item_pid2svc_res_p, 0, sizeof(*item_pid2svc_res_p));

	pid_count--;

	i = 0;
	while (i < svc->pid_count) {
		if (svc->pid[i] == pid) {
			svc->pid_count--;
			svc->pid[i] = svc->pid[ svc->pid_count ];
			log(LOG_DEBUG, "Unregistered the pid: %d -> %s (%d).\n", pid, svc->name, svc->pid_count);
			return 0;
		}
		i++;
	}

	log(LOG_ERR, "Error: Cannot find pid %d in list of \"%s\".\n", pid, svc->name);
	return ESRCH;
}

int pid_unregister_service(service_t *svc) {
	if (svc == NULL)
		return EINVAL;

	log(LOG_DEBUG, "Unregistering all pids of \"%s\"\n", svc->name)

	if (!svc->pid_count) {
		log(LOG_NOTICE, "There's no pids attached to \"%s\". (#0)\n", svc->name)
		return 0;
	}

	while (svc->pid_count--) {
		void *res;

		pidsvc_t item_pid2svc, *item_pid2svc_res_p;

		item_pid2svc.pid  = svc->pid[svc->pid_count];

		res = tfind(&item_pid2svc, &tsearch_pid2svc_bt, compar_pidsvc_pid); /* TODO: remove double-searching through the BT */
		if (res == NULL) {
			log(LOG_NOTICE, "Cannot find pid %d in internal list. Service \"%s\".\n", svc->pid[svc->pid_count], svc->name);
			continue;
		}

		item_pid2svc_res_p = *(void **)res;
		memset(item_pid2svc_res_p, 0, sizeof(*item_pid2svc_res_p));

		tdelete(&item_pid2svc, &tsearch_pid2svc_bt, compar_pidsvc_pid);

		pid_count--;
	}

	return 0;
}

/* - ptrace - */

#define ptrace_safe(errcode, request, pid, ...) {\
	errno=0;\
	if (unlikely(ptrace(request, pid, ## __VA_ARGS__) == -1))\
		if (likely(errno)) {\
			ptrace_error(svc, pid);\
			errcode;\
		}\
}

#define ptrace_safe_return(...)		ptrace_safe(return errno,	__VA_ARGS__)
#define ptrace_safe_continue(...)	ptrace_safe(continue,		__VA_ARGS__)
#define ptrace_safe_ignore(...)		ptrace_safe(NULL,		__VA_ARGS__)

int ptrace_error(service_t *svc, pid_t pid)
{
	log(LOG_EMERG, "Got error while ptrace(request, %i, ...): %s. (#0)\n", pid, strerror(errno));\
	return service_exit(svc, errno);
}

int ptrace_serviceexit(service_t *svc)
{
	log(LOG_NOTICE, "Service \"%s\" exited.\n", svc->name);\
	return 0;
}

int ptrace_postattach(service_t *svc, pid_t svc_pid)
{
	int child_status;

	pid_register(svc_pid, svc);

	/* setting up catching of forks and exits */

	ptrace_safe_return(PTRACE_SETOPTIONS,	svc_pid, NULL, PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXIT);

	/* unhalting the process */

	ptrace_safe_return(PTRACE_CONT,	svc_pid, NULL, WSTOPSIG(child_status));
	//ptrace_safe(PTRACE_CONT,	svc_pid, NULL, NULL);

	return errno;
}

int ptrace_detach(service_t *svc) {
	int i = 0;


	while (i < svc->pid_count) {
		ptrace_safe_ignore(PTRACE_CONT,		svc->pid[i],	NULL, SIGCONT);
		ptrace_safe_ignore(PTRACE_DETACH,	svc->pid[i]);
		i++;
	}

	pid_unregister_service(svc);
	return 0;
}

void ptrace_ctrl_sigpoll(int sig)
{
	return;
}

int ptrace_ctrl(void *arg)
{
	// Configuring signals
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);

	if (pthread_sigmask(SIG_BLOCK, &sigset, NULL))
		return errno;

	signal(SIGPOLL,  ptrace_ctrl_sigpoll);

	while (1) {
		int errno_waitpid;
//		siginfo_t winfo;
		service_t *svc;
		pid_t child_pid;
		int child_status;

		log(LOG_DEBUG, "ptrace_ctrl(): Waiting for event.\n");
		//if (waitid(P_ALL, 0, &winfo, WSTOPPED|WEXITED|WCONTINUED) == -1) {
		//child_pid = waitpid(svcs[0].pid[0], &child_status, WCONTINUED);
		child_pid = waitpid(-1, &child_status, __WALL);
		errno_waitpid = errno;
		if (child_pid == -1) {
			switch (errno_waitpid) {
				case ECHILD:
					break;
				default:
					log(LOG_EMERG, "Got error while waitpid(): %s. Exit.\n", strerror(errno));
					exit(errno);
			}
		}

		if (errno_waitpid == ECHILD) {
			log(LOG_DEBUG, "There're no children, but waitpid() was been called. Resetting svc_count to zero.\n");
			svc_count = 0;
			/* wait until ptrace_mutex will be unlocked */
			log(LOG_DEBUG, "ptrace_ctrl(): Waiting for children.\n");
			pthread_cond_wait(&ptrace_mutex_cond, &ptrace_mutex);
			log(LOG_DEBUG, "ptrace_ctrl(): Hooray! New child: %d.\n", ptrace_arg_attachservice_pid);
		} else {
			svc = service_bypid(child_pid);

			if (svc == NULL) {
				log(LOG_ALERT, "Cannot find service by pid %d in internal list.\n", child_pid);
				continue;
			}
			log(LOG_DEBUG, "ptrace_ctrl(): Recieved an event from \"%s\" (pid: %d).\n", svc->name, child_pid);
		}

		/* attaching to a new service if that was signalled by an another thread */
		if (ptrace_arg_attachservice_pid) {
			/* attaching to the process */

			log(LOG_DEBUG, "attaching to %d\n",	ptrace_arg_attachservice_pid);
			ptrace_safe_return(PTRACE_ATTACH,	ptrace_arg_attachservice_pid);

			if (waitpid(ptrace_arg_attachservice_pid, &child_status, 0) == -1 && errno) {
				log(LOG_ALERT, "ptrace_ctrl(): Got error on waitpid() while attaching to new service: %s\n", strerror(errno));
				service_exit(svc, errno);
				continue;
			}

			/* storing information about the process */

			ptrace_postattach(ptrace_arg_attachservice_svc, ptrace_arg_attachservice_pid);

			/* operation complete */

			ptrace_arg_attachservice_pid = 0;
			ptrace_arg_attachservice_svc = NULL;
			pthread_cond_broadcast(&ptrace_mutex_cond);
		}

		/* detaching from a service if that was signalled by an another thread */
		if (ptrace_arg_detachservice != NULL) {
			ptrace_detach(ptrace_arg_detachservice);
			ptrace_arg_detachservice = 0;
			pthread_cond_broadcast(&ptrace_mutex_cond);
		}

		if (child_pid <= 0) {
			log(LOG_DEBUG, "ptrace_ctrl(): child_pid (%i) <= 0.\n", child_pid);
			continue;
		}

		switch (PTRACE_EVENT(child_status)) {
			case 0: {
				/* caught a signal */

				log(LOG_DEBUG, "ptrace_ctrl(): \"%s\": Got a signal #%i\n", svc->name, WSTOPSIG(child_pid));
				break;
			}
			case PTRACE_EVENT_FORK: {
				/* caught a fork */

				long _newpid;
				pid_t newpid;

				log(LOG_DEBUG, "ptrace_ctrl(): \"%s\": a fork(): %d\n", svc->name, child_pid);
				ptrace_safe_continue(PTRACE_GETEVENTMSG, child_pid,	NULL, &_newpid);
				newpid = _newpid;

				log(LOG_DEBUG, "ptrace_ctrl(): \"%s\" fork()-ed: %d -> %d\n", svc->name, child_pid, newpid);
				//ptrace_safe_continue(PTRACE_DETACH,	 newpid,	NULL, NULL);
				//ptrace_postattach(svc, newpid);
				pid_register(newpid, svc);
				ptrace(PTRACE_CONT, newpid, NULL, SIGCONT);
				break;
			}
			case PTRACE_EVENT_EXIT: {
				/* caught an exit */
				ptrace_safe_continue(PTRACE_CONT, child_pid, NULL, SIGCONT);
				child_pid = waitpid(child_pid, &child_status, 0);

				log(LOG_DEBUG, "ptrace_ctrl(): \"%s\" closed the pid %d. pids left: %d.\n", svc->name, child_pid, svc->pid_count-1);
				pid_unregister(child_pid, svc);

				if (!svc->pid_count)
					ptrace_serviceexit(svc);
				continue;
			}
			default: {
				/* caught an unknown event */

				log(LOG_DEBUG, "ptrace_ctrl(): \"%s\": Got an event %i\n", svc->name, PTRACE_EVENT(child_status));
				break;
			}
		}

//		ptrace_safe_continue(PTRACE_CONT, child_pid, NULL, WSTOPSIG(child_status));
		ptrace_safe_continue(PTRACE_CONT, child_pid, NULL, SIGCONT);
	}
	return 0;
}

static inline void ptrace_ctrl_cmdnotify()
{
	pthread_cond_broadcast(&ptrace_mutex_cond);
	pthread_kill(ptrace_ctrl_thread, SIGPOLL);
	pthread_cond_wait(&ptrace_mutex_cond, &ptrace_mutex);

	return;
}

int ptrace_ctrl_attachservice(service_t *svc, pid_t svc_pid)
{
	pthread_mutex_lock(&ptrace_send_mutex);

	/* notifing the ptrace_ctrl() thread about new pid to attach */
	ptrace_arg_attachservice_pid = svc_pid;
	ptrace_arg_attachservice_svc = svc;
	ptrace_ctrl_cmdnotify();

	pthread_mutex_unlock(&ptrace_send_mutex);
	return 0;
}

int ptrace_ctrl_detachservice(service_t *svc)
{
	pthread_mutex_lock(&ptrace_send_mutex);

	ptrace_arg_detachservice = svc;
	ptrace_ctrl_cmdnotify();

	pthread_mutex_unlock(&ptrace_send_mutex);
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

	log(LOG_DEBUG, "sock_ctrl() exit\n");
	return NULL;
}

/* - service - */

int service_detach(service_t *svc)
{
	if (svc == NULL)
		return EINVAL;

	log(LOG_DEBUG, "Detaching all pids of \"%s\"\n", svc->name)

	if (!svc->pid_count) {
		log(LOG_NOTICE, "There's no pids attached to \"%s\". (#1)\n", svc->name)
		return 0;
	}

	return ptrace_ctrl_detachservice(svc);
}

static inline void service_cleanup(service_t *svc)
{
	if (svc->sock) {
		log(LOG_DEBUG, "Removing the socket of \"%s\"\n", svc->name);
		close(svc->sock);
		unlink(svc->name);
		svc->sock = 0;
	}

	return;
}

int service_exit(service_t *svc, int exitcode)
{
	switch (svc->status) {
		case SS_FREE:
		case SS_EXIT:
			break;
		default:
			service_detach(svc);

			service_cleanup(svc);
			svc->status = SS_EXIT;
			log(LOG_DEBUG, "exit: %s\n", strerror(exitcode));
			svc_count--;
	}
	return exitcode;
}

service_t *service_new(char *svc_name)
{
	time_t time_cur = time(NULL);
	char istimetocleanup = (time_cur - time_lastcleanup > INTERVAL_CLEANUP);
	int svc_nextnum_old;

	svc_nextnum_old = svc_nextnum;

	if (svc_count >= MAX_SERVICES) {
		log(LOG_ALERT, "There's no more space left to store information about running services (#0).\n");
		return NULL;
	}

	/* getting actual "svc_nextnum" and cleaning up after finished services */
	while ((svcs[svc_nextnum++].status != SS_FREE) || istimetocleanup) {
		if (svcs[svc_nextnum-1].status == SS_EXIT) {
			/* cleanup */

			void *exitcode;
			int svc_id;
			service_t *svc;
			ENTRY item_name2svc;

			svc_id = svc_nextnum-1;
			svc = &svcs[svc_id];

			item_name2svc.key  = svc->name;
			item_name2svc.data = NULL;
			hsearch_safe(item_name2svc, ENTER);
			pthread_join(svcs[svc_id].sock_thread, &exitcode);

			memset(svc, 0, sizeof(*svc));
			break;
		}

		if (svc_nextnum >= MAX_SERVICES)
			svc_nextnum = 0;

		if (svc_nextnum == svc_nextnum_old) {
			if (istimetocleanup) {
				time_lastcleanup = time_cur;
				istimetocleanup  = 0;
				continue;
			}
			log(LOG_ALERT, "There's no more space left to store information about running services (#1).\n");
			return NULL;
		}
	}

	{ /* preparing new service info structure and metadata*/

		service_t *svc;
		int svc_id;
		ENTRY item;

		svc_id = svc_nextnum-1;

		svc = &svcs[svc_id];
		svc->id     = svc_id;
		svc->status = SS_NEW;

		svc_name[MAX_SERVICENAME_LENGTH] = 0;
		strcpy(svc->name, svc_name);

		item.key  = svc->name;
		item.data = svc;
		hsearch_safe(item, ENTER);

		svc_count++;
		return svc;
	}
}

int service_attach(char *svc_name, const pid_t svc_pid) {
	service_t 	*svc 		= service_new(svc_name);

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

	return ptrace_ctrl_attachservice(svc, svc_pid);
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

	if (search_res_p == NULL) {
		errno = ESRCH;
		return NULL;
	}

	if (search_res_p->data == NULL)
		errno = ESRCH;

	return search_res_p->data;
}

service_t *service_bypid(pid_t svc_pid) {
	void *res;
	pidsvc_t item_pid2svc, *item_pid2svc_res_p;
	item_pid2svc.pid  = svc_pid;

	res = tfind(&item_pid2svc, &tsearch_pid2svc_bt, compar_pidsvc_pid);
	if (res == NULL) {
		errno = ESRCH;
		return NULL;
	}

	item_pid2svc_res_p = *(void **)res;

	return item_pid2svc_res_p->svc;
}

int service_finish(service_t *svc) {
	return kill(svc->pid[0], SIGTERM);
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

		time_lastcleanup = time(NULL);
	}

	{ /* running the monitoring thread */
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

