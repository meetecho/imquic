#include <arpa/inet.h>
#include <netdb.h>
#include "internal/network.h"
#include "internal/quic.h"

static struct addrinfo addresses[2];
static struct sockaddr_in ipv4;
static struct sockaddr_in6 ipv6;
static gboolean freed = FALSE;

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
	(void)node; (void)service; (void)hints;
	memset(addresses, 0, sizeof(addresses));
	ipv4.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr);
	ipv6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "::1", &ipv6.sin6_addr);
	addresses[0].ai_family = AF_INET6;
	addresses[0].ai_addr = (struct sockaddr *)&ipv6;
	addresses[0].ai_addrlen = sizeof(ipv6);
	addresses[0].ai_next = &addresses[1];
	addresses[1].ai_family = AF_INET;
	addresses[1].ai_addr = (struct sockaddr *)&ipv4;
	addresses[1].ai_addrlen = sizeof(ipv4);
	*result = addresses;
	freed = FALSE;
	return 0;
}

void freeaddrinfo(struct addrinfo *result) {
	g_assert(result == addresses);
	freed = TRUE;
}

int imquic_quic_create_context(imquic_network_endpoint *endpoint, imquic_configuration *config) {
	(void)endpoint; (void)config;
	return 0;
}

static void test_ipv4_after_ipv6(void) {
	imquic_configuration config = { 0 };
	config.name = "dns-test";
	config.ip = "0.0.0.0";
	config.remote_host = "dual-stack.test";
	config.remote_port = 9000;
	config.raw_quic = TRUE;
	config.alpn = "test";
	imquic_network_endpoint *endpoint = imquic_network_endpoint_create(&config);
	g_assert(freed);
	g_assert((endpoint) != NULL);
	g_assert_cmpint(endpoint->remote_address.addr.ss_family, ==, AF_INET);
	struct sockaddr_in *remote = (struct sockaddr_in *)&endpoint->remote_address.addr;
	g_assert_cmpuint(ntohl(remote->sin_addr.s_addr), ==, 0x7f000001);
	g_assert_cmpuint(ntohs(remote->sin_port), ==, 9000);
	imquic_network_endpoint_destroy(endpoint);
}

int main(int argc, char *argv[]) {
	g_test_init(&argc, &argv, NULL);
	imquic_set_log_level(0);
	g_test_add_func("/network/ipv4-after-ipv6", test_ipv4_after_ipv6);
	return g_test_run();
}
