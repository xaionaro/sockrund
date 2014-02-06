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
#include <stdlib.h>	/* atservice_exit()		*/
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

/* === configuration === */

#define SVC_MYNAME	"sockrund"
#define DIR_SOCKETS	"/run/openrc/sockrund"
//#define ENV_SVCNAME	"RC_SVCNAME"
#define SOCKET_BACKLOG	5
#define PATH_CTRLSOCK	DIR_SOCKETS"/"SVC_MYNAME".sock"

/* === portability hacks === */

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* === global variables === */

int ctrlsock = 0;

/* === code self === */

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

	if (bind(sock, (struct sockaddr *)&sock_addr, sock_addr_len))
		return -1;

	if (listen(sock, SOCKET_BACKLOG))
		return -1;

	return sock;
}

int service_run(const char const *svc_name, char *argv[]) {
	pthread_t		sock_ctrl_th	=  0;
	int			sock		=  0;
	char			sock_path[PATH_MAX];

	sprintf(sock_path, DIR_SOCKETS"/%s.sock", svc_name);	/* TODO: check svc_name length */

	#define service_exit(exitcode) { service_cleanup(); return exitcode; }
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
		pid_t pid;

		pid = fork();

		if (pid == -1) {
			fprintf(stderr, "Got error while fork()-ing: %s.\n", strerror(errno));
			service_exit(errno);
		}

		if (pid == 0) { /* the child */
			ptrace(PTRACE_TRACEME, 0, 0, 0);	/* waiting while ptrace()-ing started */
			argv++;
			execvp(argv[0], argv);
			service_exit(EXIT_FAILURE);		/* exec never returns :) */
		} else {	/* the parent */
			int child_status;

			ptrace(PTRACE_SYSCALL, pid, 0, 0);

			waitpid(pid, &child_status, 0);
			service_exit(WEXITSTATUS(child_status));
		}
	}

	service_exit(EXIT_FAILURE);	/* this's unreachable line */
}

void cleanup() {
	if (ctrlsock) {
		close(ctrlsock);
		unlink(PATH_CTRLSOCK);
		ctrlsock = 0;
	}

	return;
}

int main(int argc, char *argv[]) {
	{ /* initializating cleanup function */
		if (atexit(cleanup)) {
			fprintf(stderr, "Got error while atexit(): %s.\n", strerror(errno));
			exit(errno);
		}
	}

	{ /* checking and preparing some stuff */
		if (mkdir(DIR_SOCKETS, 0700)) {
			if (errno != EEXIST) {
				fprintf(stderr, "Cannot create directory \""DIR_SOCKETS"\": %s.\n", strerror(errno));
				exit(errno);
			}
		}
	}

	{ /* preparing the socket */
		ctrlsock = sock_prepare(PATH_CTRLSOCK);
		if(ctrlsock == -1) {
			fprintf(stderr, "Cannot create/listen an UNIX socket by path \""PATH_CTRLSOCK"\": %s.\n", strerror(errno));
			exit(errno);
		}
	}

	exit(0);
}

