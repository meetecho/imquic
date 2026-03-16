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
char *imquic_network_address_str(imquic_network_address *address, char *output, size_t outlen, gboolean add_port) {
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
	if(add_port) {
		if(address->addr.ss_family == AF_INET)
			g_snprintf(output, outlen, "%s:%"SCNu16, host, port);
		else
			g_snprintf(output, outlen, "[%s]:%"SCNu16, host, port);
	} else {
		g_snprintf(output, outlen, "%s", host);
	}
	return output;
}

uint16_t imquic_network_address_port(imquic_network_address *address) {
	if(address == NULL)
		return 0;
	/* Get port */
	if(address->addr.ss_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)&address->addr;
		return ntohs(addr->sin_port);
	} else if(address->addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&address->addr;
		return ntohs(addr->sin6_port);
	}
	IMQUIC_LOG(IMQUIC_LOG_WARN, "Unsupported family %d\n", address->addr.ss_family);
	return 0;
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
	g_strfreev(ne->alpn);
	g_free(ne->h3_path);
	g_strfreev(ne->wt_protocols);
	g_free(ne->qlog_path);
	g_hash_table_unref(ne->connections);
	g_hash_table_unref(ne->connections_by_cnx);
	if(ne->fd > -1)
		close(ne->fd);
	if(ne->qc != NULL)
		picoquic_free(ne->qc);
	g_free(ne);
}

/* Network endpoint management */
int imquic_network_endpoint_start(imquic_network_endpoint *ne) {
	if(ne == NULL)
		return -1;
	imquic_quic_next_step(ne);
	if(ne->is_server) {
		/* Nothing else to do, wait for connections */
		return 0;
	}
	/* FIXME Start the client connection */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Creating new connection\n", ne->name);
	imquic_connection *conn = imquic_connection_create(ne, NULL);
	if(conn == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error creating client connection\n", ne->name);
		return -1;
	}
	int ret = picoquic_start_client_cnx(conn->piconn);
	if(ret != 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error starting client connection: %d\n", ne->name, ret);
		return -1;
	}
	return 0;
}

void imquic_network_endpoint_add_connection(imquic_network_endpoint *ne, imquic_connection *conn, gboolean lock_mutex) {
	if(ne == NULL || conn == NULL)
		return;
	if(lock_mutex)
		imquic_mutex_lock(&ne->mutex);
	//~ imquic_refcount_increase(&conn->ref);
	g_hash_table_insert(ne->connections, conn, conn);
	g_hash_table_insert(ne->connections_by_cnx, conn->piconn, conn);
	if(lock_mutex)
		imquic_mutex_unlock(&ne->mutex);
}

void imquic_network_endpoint_remove_connection(imquic_network_endpoint *ne, imquic_connection *conn, gboolean lock_mutex) {
	if(ne == NULL || g_atomic_int_get(&ne->destroyed) || conn == NULL)
		return;
	if(lock_mutex)
		imquic_mutex_lock(&ne->mutex);
	if(g_hash_table_lookup(ne->connections, conn)) {
		imquic_connection_notify_gone(conn, 0, NULL);
		g_hash_table_remove(ne->connections, conn);
	}
	if(conn->piconn != NULL)
		g_hash_table_remove(ne->connections_by_cnx, conn->piconn);
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
			imquic_connection_close(conn, 0, NULL);
			imquic_connection_notify_gone(conn, 0, NULL);
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
	if(config->alpn == NULL && config->raw_quic) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Missing ALPN\n", config->name);
		return NULL;
	} else if(config->alpn != NULL && !config->raw_quic) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] ALPN ignored when only using WebTransport (forcing 'h3')\n", config->name);
	}
	if(config->raw_quic && strstr(config->alpn, "h3") != NULL) {
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
	if(config->sni == NULL)
		config->sni = config->remote_host;	/* FIXME */
	/* Create a socket */
	int quic_fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if(quic_fd == -1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Cannot create socket... %d (%s)\n",
			config->name, errno, g_strerror(errno));
		return NULL;
	}
	int v6only = 0;
	if(family != AF_INET && both && setsockopt(quic_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] setsockopt on socket failed... %d (%s)\n",
			config->name, errno, g_strerror(errno));
		close(quic_fd);
		return NULL;
	}
	size_t addrlen = (family == AF_INET ? sizeof(address) : sizeof(address6));
	if(bind(quic_fd, (family == AF_INET ? (struct sockaddr *)&address : (struct sockaddr *)&address6), addrlen) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Binding to port %"SCNu16" failed... %d (%s)\n",
			config->name, config->local_port, errno, g_strerror(errno));
		close(quic_fd);
		return NULL;
	}
	uint16_t port = imquic_get_fd_port(quic_fd);
	config->local_port = port;
	char ip[NI_MAXHOST] = { 0 };
	if(family == AF_INET) {
		getnameinfo((const struct sockaddr *)&address, sizeof(address),
			ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Bound to %s:%"SCNu16"\n", config->name, ip, port);
	} else {
		getnameinfo((const struct sockaddr *)&address6, sizeof(address6),
			ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Bound to [%s]:%"SCNu16"\n", config->name, ip, port);
	}
	/* Create a source to have this endpoint handled by the network loop */
	imquic_network_endpoint *ne = g_malloc0(sizeof(imquic_network_endpoint));
	ne->name = g_strdup(config->name);
	ne->is_server = config->is_server;
	ne->fd = quic_fd;
	ne->port = port;
	if(family == AF_INET) {
		ne->local_address.addrlen = sizeof(address);
		memcpy(&ne->local_address.addr, &address, ne->local_address.addrlen);
	} else {
		ne->local_address.addrlen = sizeof(address6);
		memcpy(&ne->local_address.addr, &address6, ne->local_address.addrlen);
	}
	if(!config->is_server) {
		memcpy(&ne->remote_address, &remote, sizeof(remote));
		ne->remote_port = config->remote_port;
	}
	ne->sni = g_strdup(config->sni);
	if(config->raw_quic) {
		ne->raw_quic = TRUE;
		ne->alpn = g_strsplit(config->alpn, ",", -1);
	}
	if(config->webtransport) {
		ne->webtransport = TRUE;
		if(config->h3_path && strlen(config->h3_path) > 0)
			ne->h3_path = g_strdup(config->h3_path);
		ne->wt_protocols = config->wt_protocols ? g_strsplit(config->wt_protocols, ",", -1) : NULL;
	}
	/* Check if we need to generate QLOG files */
#ifndef HAVE_QLOG
	if(config->qlog_path != NULL && (config->qlog_http3 || config->qlog_roq || config->qlog_moq)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG support for application layers (HTTP/3, RoQ, MoQ) not compiled, ignoring\n", config->name);
		config->qlog_http3 = FALSE;
		config->qlog_roq = FALSE;
		config->qlog_moq = FALSE;
	}
#endif
	if(config->qlog_path != NULL && !config->qlog_quic && !config->qlog_http3 && !config->qlog_roq && !config->qlog_moq) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG folder provided but no protocols specified, ignoring\n", config->name);
		config->qlog_path = NULL;
	}
	if(config->qlog_path != NULL) {
		/* QLOG support is split in two parts: for QUIC QLOG, we rely on
		 * what picoquic provides; for other layers under our direct control
		 * (HTTP/3, MoQ, RoQ) we create QLOG files ourselves instead. In
		 * both cases, make sure we received a folder and that it exists */
		struct stat s;
		int err = stat(config->qlog_path, &s);
		if(err == -1) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG path '%s' is not a valid folder (%d: %s), ignoring\n",
				config->name, config->qlog_path, errno, g_strerror(errno));
		} else if(!S_ISDIR(s.st_mode)) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] QLOG path '%s' is not a valid folder, ignoring\n",
				config->name, config->qlog_path);
		} else {
			ne->qlog_path = g_strdup(config->qlog_path);
		}
		if(ne->qlog_path != NULL) {
			ne->qlog_quic = config->qlog_quic;
			ne->qlog_http3 = config->qlog_http3 && ne->webtransport;
			ne->qlog_roq = config->qlog_roq;
			ne->qlog_roq_packets = config->qlog_roq && config->qlog_roq_packets;
			ne->qlog_moq = config->qlog_moq;
			ne->qlog_moq_messages = config->qlog_moq && config->qlog_moq_messages;
			ne->qlog_moq_objects = config->qlog_moq && config->qlog_moq_objects;
			ne->qlog_sequential = config->qlog_sequential;
			if(!config->qlog_quic && !ne->qlog_http3 && !ne->qlog_roq && !ne->qlog_moq) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] No protocol tracing was enabled or detected, disabling QLOG\n", config->name);
				g_free(ne->qlog_path);
				ne->qlog_path = NULL;
			} else if(config->qlog_quic && config->qlog_sequential && !ne->qlog_http3 && !ne->qlog_roq && !ne->qlog_moq) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Sequential QLOG files not supported for QUIC\n", config->name);
			}
		}
	}
	ne->connections = g_hash_table_new_full(NULL, NULL,
		NULL, (GDestroyNotify)imquic_connection_destroy);
	ne->connections_by_cnx = g_hash_table_new(NULL, NULL);
	ne->user_data = config->user_data;
	imquic_mutex_init(&ne->mutex);
	imquic_refcount_init(&ne->ref, imquic_network_endpoint_free);
	/* Create the picoquic context */
	if(imquic_quic_create_context(ne, config) < 0) {
		imquic_network_endpoint_destroy(ne);
		return NULL;
	}
	/* Done */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Endpoint created\n", config->name);
	return ne;
}

/* Callback fired when we have packets to send on a connection */
int imquic_network_send_packet(imquic_network_endpoint *ne) {
	IMQUIC_LOG(IMQUIC_LOG_DBG, "[%s] Callback fired\n", ne->name);
	uint8_t buffer[4096];
	size_t blen = 0;
	struct sockaddr_storage to = {0}, from = {0};
	int if_index = 0, ret = 0;
	while((ret = picoquic_prepare_next_packet(ne->qc, picoquic_current_time(),
			buffer, sizeof(buffer), &blen, &to, &from, &if_index, NULL, NULL)) == 0 && blen > 0) {
		int sent = sendto(ne->fd, buffer, blen, 0, (struct sockaddr *)&to, sizeof(to));
		if(sent < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error in sendto... %d (%s)\n", errno, g_strerror(errno));
		} else {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Sent %d/%zu bytes\n", sent, blen);
		}
	}
	imquic_quic_next_step(ne);
	return G_SOURCE_REMOVE;
}

