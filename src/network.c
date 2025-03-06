/*! \file   network.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Networking utilities
 * \details Implementation of the networking functionality of the QUIC
 * stack. This is where client and server instances are allocated and
 * managed, taking care of actually sending data out, and to notify upper
 * layers about new connections or data coming in. The networking stack
 * relies on a separate event loop for polling the sockets.
 *
 * \ingroup Core
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "internal/network.h"
#include "internal/loop.h"
#include "internal/quic.h"
#include "internal/utils.h"
#include "imquic/debug.h"

/* Initialization*/
static gboolean ipv6_disabled = FALSE;
void imquic_network_init(void) {
	/* Let's check if IPv6 is disabled, as we may need when creating sockets */
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if(fd < 0) {
		ipv6_disabled = TRUE;
	} else {
		int v6only = 0;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0)
			ipv6_disabled = TRUE;
	}
	if(fd >= 0)
		close(fd);
	if(ipv6_disabled) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "IPv6 disabled, will only use IPv4 sockets\n");
	}
}

void imquic_network_deinit(void) {
	/* Nothing here, for the moment */
}


/* Network address stringification */
char *imquic_network_address_str(imquic_network_address *address, char *output, size_t outlen) {
	if(address == NULL || output == NULL || outlen == 0)
		return NULL;
	/* Get host */
	char host[NI_MAXHOST];
	int s = getnameinfo((const struct sockaddr *)&address->addr, address->addrlen,
		host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	if(s != 0) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "getnameinfo() failed: %s\n", gai_strerror(s));
		return NULL;
	}
	/* Get port */
	uint16_t port = 0;
	if(address->addr.ss_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)&address->addr;
		port = ntohs(addr->sin_port);
	} else if(address->addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&address->addr;
		port = ntohs(addr->sin6_port);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Unsupported family %d\n", address->addr.ss_family);
		return NULL;
	}
	/* Serialize */
	if(address->addr.ss_family == AF_INET) {
		g_snprintf(output, outlen, "%s:%"SCNu16, host, port);
	} else {
		g_snprintf(output, outlen, "[%s]:%"SCNu16, host, port);
	}
	return output;
}


/* Helper to return fd port */
static int imquic_get_fd_port(int fd) {
	struct sockaddr_in6 server = { 0 };
	socklen_t len = sizeof(server);
	if(getsockname(fd, (struct sockaddr *)&server, &len) == -1) {
		return -1;
	}
	return ntohs(server.sin6_port);
}

/* Endpoint manipulation */
static void imquic_network_endpoint_free(const imquic_refcount *ne_ref) {
	imquic_network_endpoint *ne = imquic_refcount_containerof(ne_ref, imquic_network_endpoint, ref);
	g_free(ne->name);
	g_free(ne->sni);
	g_free(ne->alpn);
	g_free(ne->h3_path);
	g_free(ne->subprotocol);
	g_free(ne->qlog_path);
	g_hash_table_unref(ne->connections);
	imquic_tls_destroy(ne->tls);
	if(ne->fd > -1)
		close(ne->fd);
	g_free(ne);
}

void imquic_network_endpoint_add_connection(imquic_network_endpoint *ne, imquic_connection *conn, gboolean lock_mutex) {
	if(ne == NULL || conn == NULL)
		return;
	if(lock_mutex)
		imquic_mutex_lock(&ne->mutex);
	//~ imquic_refcount_increase(&conn->ref);
	g_hash_table_insert(ne->connections, conn, conn);
	if(lock_mutex)
		imquic_mutex_unlock(&ne->mutex);
}

void imquic_network_endpoint_remove_connection(imquic_network_endpoint *ne, imquic_connection *conn, gboolean lock_mutex) {
	if(ne == NULL || g_atomic_int_get(&ne->destroyed) || conn == NULL)
		return;
	if(lock_mutex)
		imquic_mutex_lock(&ne->mutex);
	if(g_hash_table_lookup(ne->connections, conn)) {
		if(ne->connection_gone)
			ne->connection_gone(conn);
		g_hash_table_remove(ne->connections, conn);
	}
	if(lock_mutex)
		imquic_mutex_unlock(&ne->mutex);
}

void imquic_network_endpoint_shutdown(imquic_network_endpoint *ne) {
	if(ne == NULL || ne->source == NULL)
		return;
	g_source_destroy((GSource *)ne->source);
	g_source_unref((GSource *)ne->source);
}

void imquic_network_endpoint_destroy(imquic_network_endpoint *ne) {
	if(ne && g_atomic_int_compare_and_exchange(&ne->destroyed, 0, 1)) {
		/* Close all connections */
		imquic_mutex_lock(&ne->mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, ne->connections);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			imquic_connection *conn = (imquic_connection *)value;
			imquic_connection_close(conn, 0, 0, NULL);
			if(ne->connection_gone)
				ne->connection_gone(conn);
			g_hash_table_iter_remove(&iter);
		}
		imquic_mutex_unlock(&ne->mutex);
		imquic_refcount_decrease(&ne->ref);
	}
}

/* Create a server or a client */
imquic_network_endpoint *imquic_network_endpoint_create(imquic_configuration *config) {
	/* Validate the configuration */
	if(config == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Can't create endpoint, missing configuration\n");
		return NULL;
	}
	if(!config->raw_quic && !config->webtransport)
		config->raw_quic = TRUE;
	if(config->name == NULL)
		config->name = "??";
	if(config->is_server && (config->cert_pem == NULL || config->cert_key == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Missing certificate/key\n", config->name);
		return NULL;
	}
	if(!config->is_server && (config->remote_host == NULL || config->remote_port == 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Missing remote host/port\n", config->name);
		return NULL;
	}
	if(config->sni == NULL)
		config->sni = "localhost";	/* FIXME */
	if(config->alpn == NULL && config->raw_quic) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Missing ALPN\n", config->name);
		return NULL;
	} else if(config->alpn != NULL && !config->raw_quic)
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] ALPN ignored when only using WebTransport (forcing 'h3')\n", config->name);
	if(config->raw_quic && !strcasecmp(config->alpn, "h3")) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] HTTP/3 is currently only supported for WebTransport\n", config->name);
		return NULL;
	}
	if(config->webtransport && config->h3_path && (strlen(config->h3_path) == 0 || *config->h3_path != '/')) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid HTTP/3 path '%s'\n", config->name, config->h3_path);
		return NULL;
	}
	if(config->early_data && !config->is_server && config->ticket_file == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Missing session ticket file for client early-data\n", config->name);
		return NULL;
	}
	/* In case we need to bind to a specific interface or IP address, validate it:
	 * by default, we bind to both IPv4 and IPv6, unless IPv6 is disabled */
	int family = ipv6_disabled ? AF_INET : AF_INET6;
	gboolean both = ipv6_disabled ? FALSE : TRUE;
	struct sockaddr_in address = {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	struct sockaddr_in6 address6 = { 0 };
	address6.sin6_family = AF_INET6;
	address6.sin6_addr = in6addr_any;
	if(config->ip != NULL) {
		/* Check if we're binding to specific addresses */
		if(!strcmp(config->ip, "0.0.0.0")) {
			family = AF_INET;
			both = FALSE;
		} else if(!strcmp(config->ip, "::")) {
			if(ipv6_disabled) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Can't bind to IPv6 address, IPv6 is disabled\n", config->name);
				return NULL;
			}
			family = AF_INET6;
			both = TRUE;
		} else {
			/* Traverse interface names and addresses */
			struct ifaddrs *ifaddr = NULL, *ifa = NULL;
			char host[NI_MAXHOST];
			gboolean found = FALSE;
			if(getifaddrs(&ifaddr) == -1) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error getting list of interfaces... %d (%s)\n",
					config->name, errno, g_strerror(errno));
				return NULL;
			}
			for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
				if(ifa->ifa_addr == NULL)
					continue;
				/* Skip interfaces which are not up and running */
				if(!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
					continue;
				if(ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)
					continue;
				int s = getnameinfo(ifa->ifa_addr,
					(ifa->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				if(s != 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] getnameinfo() failed: %s\n", config->name, gai_strerror(s));
					continue;
				}
				if(!strcmp(host, config->ip)) {
					/* Found */
					found = TRUE;
					family = ifa->ifa_addr->sa_family;
					both = FALSE;
					if(family == AF_INET) {
						struct sockaddr_in *ifa_addr = (struct sockaddr_in *)ifa->ifa_addr;
						address.sin_addr = ifa_addr->sin_addr;
					} else {
						struct sockaddr_in6 *ifa_addr = (struct sockaddr_in6 *)ifa->ifa_addr;
						memcpy(&address6, ifa_addr, sizeof(*ifa_addr));
					}
					break;
				}
			}
			freeifaddrs(ifaddr);
			if(!found) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Can't bind to '%s', IP address not found in local interfaces\n",
					config->name, config->ip);
				return NULL;
			}
		}
	}
	address.sin_port = g_htons(config->local_port);
	address6.sin6_port = g_htons(config->local_port);
	/* Resolve the remote address, if this is a client */
	imquic_network_address remote = { 0 };
	if(!config->is_server) {
		struct sockaddr_in *remote_addr = (struct sockaddr_in *)&remote.addr;
		struct sockaddr_in6 *remote_addr6 = (struct sockaddr_in6 *)&remote.addr;
		/* Perform a getaddrinfo on the address */
		struct addrinfo *result = NULL;
		gboolean resolved = FALSE;
		int res = getaddrinfo(config->remote_host, NULL, NULL, &result);
		if(res == 0) {
			/* Address resolved */
			struct addrinfo *temp = result;
			while(temp && !resolved) {
				if(result->ai_family != family && !both) {
					/* This won't work, try a different one */
					temp = temp->ai_next;
				} else if(result->ai_family == AF_INET) {
					/* IPv4 */
					resolved = TRUE;
					family = AF_INET;
					remote.addrlen = sizeof(*remote_addr);
					struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
					memcpy(remote_addr, addr, sizeof(*addr));
					remote_addr->sin_family = AF_INET;
					remote_addr->sin_port = g_htons(config->remote_port);
					break;
				} else if(result->ai_family == AF_INET6) {
					/* IPv6 */
					if(ipv6_disabled) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Can't connect to IPv6 address, IPv6 is disabled\n", config->name);
						return NULL;
					}
					resolved = TRUE;
					family = AF_INET6;
					remote.addrlen = sizeof(*remote_addr6);
					struct sockaddr_in6 *addr = (struct sockaddr_in6 *)result->ai_addr;
					memcpy(remote_addr6, addr, sizeof(*addr));
					remote_addr6->sin6_family = AF_INET6;
					remote_addr6->sin6_port = g_htons(config->remote_port);
					break;
				}
				temp = temp->ai_next;
			}
			freeaddrinfo(result);
		}
		if(res != 0 || !resolved) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error resolving '%s'... %d (%s)\n",
				config->name, config->remote_host, errno, g_strerror(errno));
			return NULL;
		}
	}
	/* Initialize the TLS stack */
	imquic_tls *tls = imquic_tls_create(config->is_server, config->cert_pem, config->cert_key, config->cert_pwd);
	if(tls == NULL)
		return NULL;
	if(config->early_data)
		imquic_tls_enable_early_data(tls, config->ticket_file);
	/* Create a socket */
	int quic_fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if(quic_fd == -1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Cannot create socket... %d (%s)\n",
			config->name, errno, g_strerror(errno));
		imquic_tls_destroy(tls);
		return NULL;
	}
	int v6only = 0;
	if(family != AF_INET && both && setsockopt(quic_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] setsockopt on socket failed... %d (%s)\n",
			config->name, errno, g_strerror(errno));
		close(quic_fd);
		imquic_tls_destroy(tls);
		return NULL;
	}
	size_t addrlen = (family == AF_INET ? sizeof(address) : sizeof(address6));
	if(bind(quic_fd, (family == AF_INET ? (struct sockaddr *)&address : (struct sockaddr *)&address6), addrlen) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Binding to port %"SCNu16" failed... %d (%s)\n",
			config->name, config->local_port, errno, g_strerror(errno));
		close(quic_fd);
		imquic_tls_destroy(tls);
		return NULL;
	}
	uint16_t port = imquic_get_fd_port(quic_fd);
	char ip[NI_MAXHOST] = { 0 };
	if(family == AF_INET) {
		getnameinfo((const struct sockaddr *)&address, sizeof(address),
			ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Bound to %s:%"SCNu16"\n", config->name, ip, port);
	} else {
		getnameinfo((const struct sockaddr *)&address6, sizeof(address6),
			ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Bound to [%s]:%"SCNu16"\n", config->name, ip, port);
	}
	if(!config->is_server) {
		if(connect(quic_fd, (struct sockaddr *)&remote.addr, remote.addrlen) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error connecting to %s... %d (%s)\n",
				config->name, imquic_network_address_str(&remote, ip, sizeof(ip)), errno, g_strerror(errno));
			close(quic_fd);
			imquic_tls_destroy(tls);
			return NULL;
		}
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connected socket to remote address %s\n",
			config->name, imquic_network_address_str(&remote, ip, sizeof(ip)));
	}
	/* Create a source to have this endpoint handled by the network loop */
	imquic_network_endpoint *ne = g_malloc0(sizeof(imquic_network_endpoint));
	ne->name = g_strdup(config->name);
	ne->is_server = config->is_server;
	ne->fd = quic_fd;
	ne->port = port;
	if(!config->is_server)
		memcpy(&ne->remote_address, &remote, sizeof(remote));
	ne->tls = tls;
	ne->sni = g_strdup(config->sni);
	if(config->raw_quic) {
		ne->raw_quic = TRUE;
		ne->alpn = g_strdup(config->alpn);
	}
	if(config->webtransport) {
		ne->webtransport = TRUE;
		if(config->h3_path && strlen(config->h3_path) > 0)
			ne->h3_path = g_strdup(config->h3_path);
		ne->subprotocol = config->subprotocol ? g_strdup(config->subprotocol) : NULL;
	}
	if(config->qlog_path != NULL) {
#ifndef HAVE_QLOG
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG support not compiled, ignoring\n", config->name);
#else
		/* Make sure that it's a folder, if this is a server, or a file if a client */
		struct stat s;
		int err = stat(config->qlog_path, &s);
		if(config->is_server) {
			if(err == -1) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG path '%s' is not a valid folder (%d: %s), ignoring\n",
					config->name, config->qlog_path, errno, g_strerror(errno));
			} else if(!S_ISDIR(s.st_mode)) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG path '%s' is not a valid folder, ignoring\n",
					config->name, config->qlog_path);
			} else {
				ne->qlog_path = g_strdup(config->qlog_path);
			}
		} else {
			if(err == 0 && S_ISDIR(s.st_mode)) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG path '%s' is a folder, ignoring\n",
					config->name, config->qlog_path);
			} else {
				ne->qlog_path = g_strdup(config->qlog_path);
			}
		}
#endif
	}
	ne->connections = g_hash_table_new_full(NULL, NULL,
		NULL, (GDestroyNotify)imquic_connection_destroy);
	ne->user_data = config->user_data;
	imquic_mutex_init(&ne->mutex);
	imquic_refcount_init(&ne->ref, imquic_network_endpoint_free);
	/* Done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Endpoint created\n", config->name);
	return ne;
}

/* Helper to send data */
int imquic_network_send(imquic_connection *conn, uint8_t *bytes, size_t blen) {
	if(conn == NULL || conn->socket == NULL || conn->socket->fd < 0 || bytes == NULL || blen == 0)
		return -1;
	int sent = 0;
	if((sent = sendto(conn->socket->fd, bytes, blen, 0,
			(struct sockaddr *)&conn->peer.addr, conn->peer.addrlen)) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error in sendto... %d (%s)\n", errno, g_strerror(errno));
	} else {
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Sent %d/%zu bytes\n", sent, blen);
	}
	return sent;
}
