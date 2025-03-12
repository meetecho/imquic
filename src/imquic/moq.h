/*! \file   moq.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic MoQ public interface (headers)
 * \details Public interface to the Media Over QUIC (MoQ) native support
 * in the imquic library. This is where public functions are callbacks to
 * interact with the MoQ features of the library are defined.
 *
 * \ingroup API MoQ Core
 *
 * \page moqapi Native support for Media Over QUIC (MoQ)
 * As explained in the \ref publicapi, \ref imquic_create_server and \ref imquic_create_client
 * are the methods you can use to create a new, generic, QUIC server or
 * client, with the related callbacks to be notified about what happens
 * on new or existing connections. That API assumes you'll be entirely
 * responsible of the application level protocol details, though.
 *
 * Out of the box, imquic provides native support for a few specific
 * protocols, meaning it can deal with the lower level details of the
 * application level protocol, while exposing a simpler and higher level
 * API to use the protocol features programmatically. Medias Over QUIC is
 * one of those protocols.
 *
 * When you want to use the native MoQ features of imquic, you must not
 * use the generic functions and callbacks, but will need to use the MoQ
 * variants defined in this page instead. Specifically, to create a MoQ
 * server you won't use \ref imquic_create_server, but will use \ref imquic_create_moq_server
 * instead; likewise, a \ref imquic_create_moq_client variant exists for creating
 * MoQ clients too.
 *
 * It's important to point out, though, that in MoQ there's a clear distinction
 * between the QUIC role (client or server) and the MoQ role (publisher,
 * subscriber, relay). The above mentioned methods specify the QUIC role,
 * while the MoQ role is configured reacting to one of the specific MoQ
 * callbacks in the library.
 *
 * Speaking of callbacks, considering the library needs to take care
 * of the MoQ protocol internally, attempting to use the generic callback
 * setters on a MoQ endpoint will do nothing, and show an error on the
 * logs: you'll need to use the MoQ specific callbacks, in order to let
 * the library do its job, and expose higher level functionality via
 * API instead. This means that, for instance, to be notified about a new
 * MoQ connection (whether you're a client or a server), you'll use
 * \ref imquic_set_new_moq_connection_cb, while to be notified about connections
 * being closed you'll need to use \ref imquic_set_moq_connection_gone_cb instead.
 * The same considerations made on reference-counting connections in generic
 * callbacks applies here too, since the same structs are used for endpoints
 * and connections: it's just the internals that are different. Starting
 * the endpoint after configuring the callbacks, instead, works exactly
 * the same way as in the generic API, meaning you'll be able to use \ref imquic_start_endpoint.
 *
 * What's important to point out is that being notified about a new MoQ
 * connection won't make it usable right away: it's just an indication that
 * a QUIC or WebTransport connection was successfully established, but no
 * MoQ message has been exchanged yet. Most importantly, that callback
 * precedes the MoQ handshake/setup, which means that's the perfect place
 * to specify the MoQ role and version of your endpoint, which you can do
 * with a call to \ref imquic_moq_set_role and \ref imquic_moq_set_version
 * respectively. As soon as you return from the callback function, in case
 * the application is a client the internal MoQ stack in imquic will
 * perform the MoQ setup accordingly; for servers it will wait for a
 * connection from a client to do so.
 *
 * To be notified when the MoQ session has been established, and MoQ
 * messages can finally be exchanged, you can use the \ref imquic_set_moq_ready_cb
 * callback setter. As soon as that callback fires, you'll be able to start
 * exchanging messages, e.g., to subscribe to a namespace or publish one.
 *
 * Depending on the MoQ role, you can configure different callbacks and
 * use different methods to send MoQ requests of your own. For instance,
 * a relay may want to be aware of incomming \c ANNOUNCE requests, but
 * a publisher won't care; at the same time, a publisher will need to
 * be aware of incoming \c SUBSCRIBE requests, but a subscriber won't
 * need/care about those. The following sections will cover the different
 * callbacks and methods you can use as a publisher and a subscriber,
 * taking into account that a relay is basically a mix of the two, which
 * means it will probably implement a mix of both, if not all of them,
 * depending on what it's configured to do.
 *
 * \section moqns Namespace tuples and track names
 *
 * Without delving too much into the details of the specification (please
 * refer to the draft for that), key identifiers in MoQ are the namespace
 * a publisher can advertise, and the track names that publishers may
 * publish within the context of those namespaces.
 *
 * A namespace is formatted as a tuple, where this tuple will have a
 * hierarchical meaning: a tuple of <code>Italy / Meetecho / Lorenzo</code>,
 * for instance, will be made of three different namespace blocks (<code>Italy</code>,
 * <code>Meetecho</code>, <code>Lorenzo</code>), which give context to
 * the whole tuple (Lorenzo is part of Meetecho, Meetecho is part of Italy).
 * This is particularly important because it can give context to applications
 * as well, and to requests like \c SUBSCRIBE_ANNOUNCES : if we imagine
 * a chat application, for instance, we may have a tuple like
 * <code>moq-chat / 1234 / Lorenzo</code> to indicate that Lorenzo is
 * in room \c 1234 of application <code>moq-chat</code>, which means that
 * anyone sending a \c SUBSCRIBE_ANNOUNCES for the partial tuple
 * <code>moq-chat / 1234</code> will be notified when Lorenzo announces
 * and unannounces their presence in that context.
 *
 * In the imquic MoQ integration, this is made possible using the
 * \ref imquic_moq_namespace structure, where each instance identifies
 * a specific namespace that can be part of a linked list implementing
 * the actual tuple: building a tuple is a matter of adding multiple
 * \ref imquic_moq_namespace instances, and using the \c next pointer to
 * point to the next namespace in the tuple. The demos provide examples
 * of how this can be used. Of course, a namespace can be built as a
 * tuple of 1, with no further part set in the \c next pointer.
 *
 * Track names are simpler to address, instead, and can be addressed using
 * the \ref imquic_moq_name structure.
 *
 * Both namespaces and tuples are formatted in the respective structures
 * as array of bytes of a specific length: while most of the times they'll
 * be strings for the sake of simplicity (which is what we do in our demos
 * too, for instance), the specification doesn't make that assumption,
 * and so the library doesn't either.
 *
 * \section moqpub MoQ Publishers
 *
 * In MoQ, a publisher is an endpoint that announces a specific namespace,
 * and reacts to incoming subscriptions to specific tracks of that namespace
 * by sending objects, possibly using different multiplexing/forwarding modes.
 * This means that, in principle, it will need to be able to send
 * \c ANNOUNCE and \c UNANNOUNCE requests, be notified about the result
 * of those requests and incoming subscriptions, send responses to
 * subscriptions and send objects.
 *
 * In order to be advertised as a publisher, the role in MoQ must be
 * set accordingly. This means passing \c IMQUIC_MOQ_PUBLISHER to the
 * \ref imquic_moq_set_role function, e.g., when the connection is available:
 *
\verbatim
	static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
		imquic_connection_ref(conn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection\n", imquic_get_connection_name(conn));
		imquic_moq_set_role(conn, IMQUIC_MOQ_PUBLISHER);
	}
\endverbatim
 *
 * You can also specificy a version using the \ref imquic_moq_set_role function
 * in the same place. By default, the MoQ stack will set the version to
 * \c IMQUIC_MOQ_VERSION_ANY , which means that for clients it will offer
 * all supported versions higher than v06, while for servers it will accept the first
 * offered among the supported ones (still if higher than v06); a "legacy" version
 * called \c IMQUIC_MOQ_VERSION_ANY_LEGACY is available, to negotiate any supported
 * version that is lower than v06. At the time of writing, this stack
 * supports MoQ versions from v03 ( \c IMQUIC_MOQ_VERSION_03 ) up to
 * v10 ( \c IMQUIC_MOQ_VERSION_10 ), but not all versions will be supported
 * forever. It should also be pointed out that not all features of all
 * versions are currently supported, so there may be some missing functionality
 * depending on which version you decide to negotiate. The \c IMQUIC_MOQ_VERSION_MIN
 * and \c IMQUIC_MOQ_VERSION_MAX defines can be used to programmatically
 * check the minimum and maximum supported versions.
 *
 * Speaking of callbacks (since those must be configured before starting
 * the imquic endpoint), there are two different callbacks that need to
 * be configured to know if an \c ANNOUNCE request was successful:
 *
 * - \ref imquic_set_announce_accepted_cb configures the callback to be notified
 * about the request being successful, while
 * - \ref imquic_set_announce_error_cb configures the callback to be notified
 * when an \c ANNOUNCE fails instead.
 *
 * Both callbacks will reference a \ref imquic_moq_namespace object with
 * info on the namespace they're referring to (which will typically be
 * the same one sent in a previous \c ANNOUNCE request).
 *
 * To deal with incoming subscriptions, instead, you can configure a callback
 * for intercepting incoming \c SUBSCRIBE requests via \ref imquic_set_incoming_subscribe_cb,
 * and another for intercepting an \c UNSUBSCRIBE via \ref imquic_set_incoming_unsubscribe_cb.
 * In both cases, the publisher is supposed to answer with either a success or an error.
 * \c FETCH subscriptions can be tracked using \ref imquic_set_incoming_standalone_fetch_cb
 * (for standalone \c FETCH requests) or \ref imquic_set_incoming_joining_fetch_cb
 * (for joining \c FETCH requests), while a \c FETCH_CANCEL can be
 * intercepted via \ref imquic_set_incoming_fetch_cancel_cb.
 *
 * That said, once callbacks have been configured, the endpoint started, and the publisher
 * role set, a publisher can start sending requests. To announce a new
 * namespace they'll be responsible for, they can use \ref imquic_moq_announce;
 * the \ref imquic_moq_unannounce request, instead, notifies the peer (e.g.,
 * a relay), that the publisher is not serving that namespace anymore.
 * Both will reference the namespace in a \ref imquic_moq_namespace property.
 *
 * When a subscriber decides to subscribe to a track in the publisher's
 * namespace, and the publisher is notified via the previously set
 * callback, they can decide to either accept it (and so start serving
 * objects) or reject it (e.g., because the track doesn't exist, or
 * because the provided authentication info is incorrect). Accepting
 * a subscription can be done via \ref imquic_moq_accept_subscribe, while
 * it can be rejected with \ref imquic_moq_reject_subscribe.
 * While an incoming subscribe will include more info to address a specific
 * resource (most importantly the namespace in \ref imquic_moq_namespace
 * and the track name in \ref imquic_moq_name), a \c subscribe_id integer
 * will act as a "shortcut" to address that specific subscription, both
 * in upcoming events (e.g., when notified about a will to unsubscribe)
 * and when sending responses or delivering objects.
 *
 * Sending objects can be done with a call to \ref imquic_moq_send_object.
 * At the time of writing, MoQ comes with different multiplexing modes
 * for sending an object (e.g., \c DATAGRAM , a \c STREAM per object,
 * a \c STREAM per group or a \c STREAM per track). The \ref imquic_moq_send_object
 * request hides the specifics of how the object is serialized over the
 * wire, as it just expects the \ref imquic_moq_delivery mode as one
 * of the properties set on the object to send. Besides the delivery
 * mode, the object itself will need to be filled with the relevant
 * MoQ object data (e.g., subscribe_id, object_id, group_id, etc.), as
 * that info will be serialized accordingly, depending on the multiplexing
 * mode. Depending on the negotiated version, only a subset of the
 * properties may actually be serialized on the wire, while others may
 * be dropped.
 *
 * \section moqsub MoQ Subscribers
 *
 * In MoQ, a subscriber is an endpoint that subscribes to one or more
 * tracks within a namespace, for the purpose of receiving objects from
 * a publisher, often via a relay. This means that, assuming it knows
 * using out-of-band mechanisms which namespaces and tracks are available,
 * it should be able to send \c SUBSCRIBE and \c UNSUBSCRIBE requests
 * (and/or \c FETCH and \c FETCH_CANCEL for retrieving past objects),
 * be prepared to receive responses to those requests, and have a way
 * of receiving MoQ objects to consume. It can also ask a relay to be
 * notified when specific namespaces (or namespaces prefixed by a specific
 * tuple) become available, via \c SUBSCRIBE_ANNOUNCES and
 * \c UNSUBSCRIBE_ANNOUNCES requests.
 *
 * In order to be advertised as a subscriber, the role in MoQ should be
 * set accordingly. This means passing \c IMQUIC_MOQ_SUBSCRIBER to the
 * \ref imquic_moq_set_role function, e.g., when the connection is available:
 *
\verbatim
	static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
		imquic_connection_ref(conn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection\n", imquic_get_connection_name(conn));
		imquic_moq_set_role(conn, IMQUIC_MOQ_SUBSCRIBER);
	}
\endverbatim
 *
 * Speaking of callbacks (since those must be configured before starting
 * the imquic endpoint), there are three different callbacks that can be
 * configured to know the outcome of, or the progression of, a \c SUBSCRIBE
 * request:
 *
 * - \ref imquic_set_subscribe_accepted_cb configures the callback to be notified
 * about the request being successful;
 * - \ref imquic_set_subscribe_error_cb configures the callback to be notified
 * about the request being rejected (e.g., because the track doesn't exist,
 * or the provided athentication info was incorrect);
 * - \ref imquic_set_subscribe_done_cb configures the callback to be notified
 * about a subscription being completed (currently unused, as also the
 * subjects of discussions within the MoQ standardization efforts).
 *
 * All those callbacks refer to the \c subscribe_id identifier that was
 * previously mapped to that subscription (more on that later).
 *
 * Similar callbacks are available for when a \c SUBSCRIBE_ANNOUNCES has
 * been sent, namely \ref imquic_set_subscribe_announces_accepted_cb,
 * \ref imquic_set_subscribe_announces_error_cb. It's worth pointing out
 * that if a subscriber expressed interest in getting info on \c ANNOUNCE
 * requests related to specific tuple namespaces, it should also configure the
 * \ref imquic_set_incoming_announce_cb and \ref imquic_set_incoming_unannounce_cb
 * we introduced in the publisher section before.
 *
 * The outcome of \c FETCH requests can be intercepted via the following
 * callbacks instead:
 *
 * - \ref imquic_set_fetch_accepted_cb configures the callback to be notified
 * about the request being successful;
 * - \ref imquic_set_fetch_error_cb configures the callback to be notified
 * about the request being rejected (e.g., because the track doesn't exist,
 * or the provided athentication info was incorrect).
 *
 * When successfully subscribed to something, a subscriber may receive
 * MoQ objects as part of that subscription. Independently of how that
 * object was multiplexed (something we discussed when introducing
 * \ref moqpub), a specific callback can be configured to be notified
 * about incoming objects, using \ref imquic_set_incoming_object_cb. Any
 * time a new object is available, that callback function will be invoked,
 * where all the relevant info (identifiers and payload) will be made
 * available in a \ref imquic_moq_object instance. The \c delivery property
 * will specify how the object was delivered, in case that's important.
 *
 * Coming to active requests, to issue a \c SUBSCRIBE request the subscriber
 * must provided the information to uniquely address the resource
 * they're interested in (the namespace via \ref imquic_moq_namespace,
 * the track name via \ref imquic_moq_name and, if needed, the authentication
 * info via \ref imquic_moq_auth_info), but at the same time they should
 * also provide unique \c subscribe_id and \c track_alias numeric identifiers
 * to act as shortcuts to address that subscription in subsequent responses,
 * events and incoming objects. Subscribing can be done with a call to the
 * \ref imquic_moq_subscribe function, while to unsubscribe the corresponding
 * \ref imquic_moq_unsubscribe function can be used instead.
 *
 * Issuing \c FETCH related requests is similar, as \ref imquic_moq_standalone_fetch
 * and \ref imquic_moq_joining_fetch allow you to try and fetch some objects
 * (in standalone or joining more, respectively), while \ref imquic_moq_cancel_fetch
 * is what you use to stop the delivery and cancel the request. Just as
 * with \c SUBSCRIBE requests, a \c subscribe_id identifier is used to
 * address a specific \c FETCH context. Notice that for a joining \c FETCH
 * you need to provide an existing \c SUBSCRIBE identifier as well.
 *
 * \section moqrelay MoQ Relays
 *
 * In MoQ, a relay is an endpoint that can act as both a publisher and
 * a subscriber at the same time. It can act as an intermediary for
 * subscription requests on behalf of a publisher, for instance: to make
 * a simple example, a publisher may announce a specific namespace to
 * a relay, which will then make it available to interested subscribers
 * (or to other relays). If multiple subscribers are interested in the
 * same content, the relay may only send a single \c SUBSCRIBE request
 * back to the publisher, and then selectively forward the same objects
 * it will receive to all interested subscribers, potentially caching
 * them as well. Keeping track of announced namespaces, a relay usually
 * also advertizes their presence to subscribers that sent a
 * \c SUBSCRIBE_ANNOUNCES request matching the tuple.
 *
 * In a nutshell, this means that, from a functional perspective, a
 * relay will need to be able to act both as a publisher and a subscriber
 * at the same time, which means it will probably implement the callbacks
 * of both, and use the requests of both as well (e.g., to relay objects
 * it received on one connection to other connections). As such, you can
 * refer to the documentation provided in the previous two sections for
 * more details.
 *
 * What's important to point out, though, is that in order to be
 * advertised as relay, the role in MoQ should be set accordingly. This
 * means passing \c IMQUIC_MOQ_PUBSUB to the \ref imquic_moq_set_role function,
 * e.g., when the connection is available:
 *
\verbatim
	static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
		imquic_connection_ref(conn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection\n", imquic_get_connection_name(conn));
		imquic_moq_set_role(conn, IMQUIC_MOQ_PUBSUB);
	}
\endverbatim
 *
 */

#ifndef IMQUIC_MOQ_H
#define IMQUIC_MOQ_H

#include "imquic.h"

/*! \brief MoQ Track Namespace */
typedef struct imquic_moq_namespace {
	/*! \brief Namespace data (typically a non-null terminated string) */
	uint8_t *buffer;
	/*! \brief Size of the namespace data */
	size_t length;
	/*! \brief Next namespace in this list, if this is a tuple */
	struct imquic_moq_namespace *next;
} imquic_moq_namespace;

/*! \brief MoQ Track Name */
typedef struct imquic_moq_name {
	/*! \brief Name data (typically a non-null terminated string) */
	uint8_t *buffer;
	/*! \brief Size of the name data */
	size_t length;
} imquic_moq_name;

/*! \brief MoQ Auth Info */
typedef struct imquic_moq_auth_info {
	/*! \brief Auth info data (typically a non-null terminated string) */
	uint8_t *buffer;
	/*! \brief Size of the auth info data */
	size_t length;
} imquic_moq_auth_info;

/*! \brief MoQ Group/Object couple (for ranges) */
typedef struct imquic_moq_position {
	uint64_t group;
	uint64_t object;
} imquic_moq_position;

/*! \brief MoQ FETCH range (from where to where) */
typedef struct imquic_moq_fetch_range {
	/*! \brief Start group/object */
	imquic_moq_position start;
	/*! \brief End group/object */
	imquic_moq_position end;
} imquic_moq_fetch_range;

/*! \brief Ways of sending objects */
typedef enum imquic_moq_delivery {
	/*! \brief A single object on a \c DATAGRAM */
	IMQUIC_MOQ_USE_DATAGRAM,
	/*! \brief A single object on a \c STREAM (only before v06) */
	IMQUIC_MOQ_USE_STREAM,
	/*! \brief All objects of the same group on the same \c STREAM (only before v06) */
	IMQUIC_MOQ_USE_GROUP,
	/*! \brief All objects of the same subgroup on the same \c STREAM (v06 and v07 only) */
	IMQUIC_MOQ_USE_SUBGROUP,
	/*! \brief All objects of the same track on the same \c STREAM (only before v07) */
	IMQUIC_MOQ_USE_TRACK,
	/*! \brief All fetched objects on the same \c STREAM (only v07) */
	IMQUIC_MOQ_USE_FETCH
} imquic_moq_delivery;
/*! \brief Helper function to serialize to string the name of a imquic_moq_delivery property.
 * @param type The imquic_moq_delivery property
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_delivery_str(imquic_moq_delivery type);

/*! \brief MoQ Object status */
typedef enum imquic_moq_object_status {
	/*! \brief Normal object */
	IMQUIC_MOQ_NORMAL_OBJECT = 0x0,
	/*! \brief Object doesn't exist */
	IMQUIC_MOQ_OBJECT_DOESNT_EXIST = 0x1,
	/*! \brief End of group */
	IMQUIC_MOQ_END_OF_GROUP = 0x3,
	/*! \brief End of track and group */
	IMQUIC_MOQ_END_OF_TRACK_AND_GROUP = 0x4,
	/*! \brief End of track */
	IMQUIC_MOQ_END_OF_TRACK = 0x5,
} imquic_moq_object_status;
/*! \brief Helper function to serialize to string the name of a imquic_moq_object_status property.
 * @param status The imquic_moq_object_status property
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_object_status_str(imquic_moq_object_status status);

/*! \brief MoQ Object Extension
 * \note This may contain info related to different MoQ versions, and so
 * should be considered a higher level abstraction that the internal
 * MoQ stack may (and often will) use and notify differently */
typedef struct imquic_moq_object_extension {
	/*! \brief MoQ extension ID */
	uint32_t id;
	/*! \brief Extension value, which could be either a number (even
	 * extension ID) or an octet of data with length (odd extension ID) */
	union {
		uint64_t number;
		struct imquic_moq_object_extension_data {
			uint64_t length;
			uint8_t *buffer;
		} data;
	} value;
} imquic_moq_object_extension;
/*! \brief Helper mode to parse an extensions buffer to a GList of imquic_moq_object_extension
 * \note The caller owns the list, and is responsible of freeing it and its content
 * @param extensions The buffer containing the extensions data
 * @param elen The size of the buffer containing the extensions data
 * @returns A GList instance containing a set of imquic_moq_object_extension, if successful, or NULL if no extensions were found */
GList *imquic_moq_parse_object_extensions(uint8_t *extensions, size_t elen);
/*! \brief Helper mode to craft an extensions buffer out of a GList of imquic_moq_object_extension
 * @param[in] extensions The buffer containing the extensions data
 * @param[out] bytes The buffer to write the extensions data to
 * @param[in] blen The size of the buffer to write to
 * @returns How many bytes were written, if successful */
size_t imquic_moq_build_object_extensions(GList *extensions, uint8_t *bytes, size_t blen);

/*! \brief MoQ Object
 * \note This may contain info related to different MoQ versions, and so
 * should be considered a higher level abstraction that the internal
 * MoQ stack may (and often will) use and notify differently */
typedef struct imquic_moq_object {
	/*! \brief MoQ subscribe_id */
	uint64_t subscribe_id;
	/*! \brief MoQ track_alias */
	uint64_t track_alias;
	/*! \brief MoQ group_id */
	uint64_t group_id;
	/*! \brief MoQ subgroup_id (v06 and v07 only) */
	uint64_t subgroup_id;
	/*! \brief MoQ object_id */
	uint64_t object_id;
	/*! \brief MoQ object status */
	imquic_moq_object_status object_status;
	/*! \brief MoQ object_sent_order (v03 and v04 only) */
	uint64_t object_send_order;
	/*! \brief MoQ publisher priority (only after v05) */
	uint8_t priority;
	/*! \brief MoQ object payload */
	uint8_t *payload;
	/*! \brief Size of the MoQ object payload */
	size_t payload_len;
	/*! \brief MoQ object extensions, if any (only since v08) */
	uint8_t *extensions;
	/*! \brief Size of the MoQ object extensions (only since v08) */
	size_t extensions_len;
	/*! \brief Count of the MoQ object extensions (only v08, deprecated in v09) */
	size_t extensions_count;
	/*! \brief How to send this object (or how it was received) */
	imquic_moq_delivery delivery;
	/*! \brief Whether this signals the end of the stream */
	gboolean end_of_stream;
} imquic_moq_object;

/** @name MoQ endpoints management
 */
///@{
/*! \brief Method to create a new MoQ server, using variable arguments to dictate
 * what the server should do (e.g., port to bind to, ALPN, etc.). Variable
 * arguments are in the form of a sequence of name-value started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE , e.g.:
 \verbatim
	imquic_server *server = imquic_create_moq_server("moq-relay",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, cert_pem,
		IMQUIC_CONFIG_TLS_KEY, cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, cert_pwd,
		IMQUIC_CONFIG_LOCAL_PORT, 9000,
		IMQUIC_CONFIG_WEBTRANSPORT, TRUE,
		IMQUIC_CONFIG_DONE, NULL);
 \endverbatim
 * to create a QUIC server that will automatically negotiate MoQ over
 * WebTransport. Notice that the MoQ role (publisher, subscriber or relay)
 * is not set here: this is only specifying the QUIC role (server). For
 * the MoQ role, see the imquic_set_new_moq_connection_cb callback and
 * imquic_moq_set_role. Again, as with imquic_create_server this will
 * only create the resource, but not actually start the server: before doing
 * that, you'll need to configure the callbacks for the events you're
 * interested in (in this case, MoQ specific), and then use imquic_start_endpoint to
 * start the QUIC server (which will wait for incoming connections).
 * @note This will create a full, internal, MoQ stack on top of imquic,
 * meaning that the MoQ Transport protocol will be handled natively by
 * imquic for you, providing a high level interface to the features of
 * the protocol itself. If you want to only use imquic as a QUIC/WebTrasport
 * protocol, and implement MoQ yourself, then you'll need to use
 * imquic_create_server or imquic_create_client instead.
 * @param[in] name The endpoint name (if NULL, a default value will be set)
 * @returns A pointer to a imquic_server object, if successful, NULL otherwise */
imquic_server *imquic_create_moq_server(const char *name, ...);
/*! \brief Method to create a new MoQ client, using variable arguments to dictate
 * what the client should do (e.g., address to connect to, ALPN, etc.). Variable
 * arguments are in the form of a sequence of name-value started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE , e.g.:
 \verbatim
	imquic_server *client = imquic_create_moq_client("moq-sub",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, cert_pem,
		IMQUIC_CONFIG_TLS_KEY, cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, cert_pwd,
		IMQUIC_CONFIG_REMOTE_HOST, "127.0.0.1",
		IMQUIC_CONFIG_REMOTE_PORT, 9000,
		IMQUIC_CONFIG_WEBTRANSPORT, TRUE,
		IMQUIC_CONFIG_HTTP3_PATH, "/moq",
		IMQUIC_CONFIG_DONE, NULL);

 \endverbatim
 * to create a QUIC client that will automatically negotiate MoQ over
 * WebTransport. Notice that the MoQ role (publisher, subscriber or relay)
 * is not set here: this is only specifying the QUIC role (client). For
 * the MoQ role, see the imquic_set_new_moq_connection_cb callback and
 * imquic_moq_set_role. Again, as with imquic_create_client this will only
 * create the resource, but not actually start the connection: before doing
 * that, you'll need to configure the callbacks for the events you're
 * interested in (in this case, MoQ specific), and then use imquic_start_endpoint to
 * start the QUIC client (which will attempt a connection).
 * @note This will create a full, internal, MoQ stack on top of imquic,
 * meaning that the MoQ Transport protocol will be handled natively by
 * imquic for you, providing a high level interface to the features of
 * the protocol itself. If you want to only use imquic as a QUIC/WebTrasport
 * protocol, and implement MoQ yourself, then you'll need to use
 * imquic_create_server or imquic_create_client instead.
 * @param[in] name The endpoint name (if NULL, a default value will be set)
 * @returns A pointer to a imquic_client object, if successful, NULL otherwise */
imquic_client *imquic_create_moq_client(const char *name, ...);

/*! \brief Configure the callback function to be notified about new MoQ connections
 * on the configured endpoint. For a server, it will be triggered any time
 * a client successfully connects to the server; for a client, it will
 * be triggered when the client successfully connects to the server. Notice
 * that this precedes the MoQ setup/handshakes, which means this is where
 * you need to configure the MoQ role via imquic_moq_set_role. You'll need
 * to wait until the callback set in imquic_set_moq_ready_cb is fired,
 * before being able to use the MoQ API for publishing/subscribing.
 * @note This is a good place to obtain the first reference to a connection.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param new_moq_connection Pointer to the function that will be invoked on the new MoQ connection */
void imquic_set_new_moq_connection_cb(imquic_endpoint *endpoint,
	void (* new_moq_connection)(imquic_connection *conn, void *user_data));
/*! \brief Configure the callback function to be notified when a MoQ connection
 * has been successfully established. After this, the MoQ APIs can be used
 * to start exchanging MoQ messages.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param moq_ready Pointer to the function that will be invoked when MoQ is ready to be used */
void imquic_set_moq_ready_cb(imquic_endpoint *endpoint,
	void (* moq_ready)(imquic_connection *conn));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c ANNOUNCE request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_announce Pointer to the function that will handle the incoming \c ANNOUNCE */
void imquic_set_incoming_announce_cb(imquic_endpoint *endpoint,
	void (* incoming_announce)(imquic_connection *conn, imquic_moq_namespace *tns));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c ANNOUNCE_CANCEL request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_announce_cancel Pointer to the function that will handle the incoming \c ANNOUNCE_CANCEL */
void imquic_set_incoming_announce_cancel_cb(imquic_endpoint *endpoint,
	void (* incoming_announce_cancel)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason));
/*! \brief Configure the callback function to be notified when an
 * \c ANNOUNCE we previously sent was accepted
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param announce_accepted Pointer to the function that will fire when an \c ANNOUNCE is accepted */
void imquic_set_announce_accepted_cb(imquic_endpoint *endpoint,
	void (* announce_accepted)(imquic_connection *conn, imquic_moq_namespace *tns));
/*! \brief Configure the callback function to be notified when an
 * \c ANNOUNCE we previously sent was rejected with an error
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param announce_error Pointer to the function that will fire when an \c ANNOUNCE is rejected */
void imquic_set_announce_error_cb(imquic_endpoint *endpoint,
	void (* announce_error)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c UNANNOUNCE request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_unannounce Pointer to the function that will handle the incoming \c UNANNOUNCE */
void imquic_set_incoming_unannounce_cb(imquic_endpoint *endpoint,
	void (* incoming_unannounce)(imquic_connection *conn, imquic_moq_namespace *tns));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c SUBSCRIBE request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_subscribe Pointer to the function that will handle the incoming \c SUBSCRIBE */
void imquic_set_incoming_subscribe_cb(imquic_endpoint *endpoint,
	void (* incoming_subscribe)(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth));
/*! \brief Configure the callback function to be notified when an
 * \c SUBSCRIBE we previously sent was accepted
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param subscribe_accepted Pointer to the function that will fire when an \c SUBSCRIBE is accepted */
void imquic_set_subscribe_accepted_cb(imquic_endpoint *endpoint,
	void (* subscribe_accepted)(imquic_connection *conn, uint64_t subscribe_id, uint64_t expires, gboolean descending));
/*! \brief Configure the callback function to be notified when an
 * \c SUBSCRIBE we previously sent was rejected with an error
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param subscribe_error Pointer to the function that will fire when an \c SUBSCRIBE is rejected */
void imquic_set_subscribe_error_cb(imquic_endpoint *endpoint,
	void (* subscribe_error)(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason, uint64_t track_alias));
/*! \brief Configure the callback function to be notified when an
 * \c SUBSCRIBE we previously sent is now done
 * @note Currently unused, considering there are discussions in the MoQ
 * standardization efforts on whether this is actually useful or not,
 * or if it even works at all.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param subscribe_done Pointer to the function that will fire when an \c SUBSCRIBE is done */
void imquic_set_subscribe_done_cb(imquic_endpoint *endpoint,
	void (* subscribe_done)(imquic_connection *conn, uint64_t subscribe_id, int status_code, uint64_t streams_count, const char *reason));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c UNSUBSCRIBE request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_unsubscribe Pointer to the function that will handle the incoming \c UNSUBSCRIBE */
void imquic_set_incoming_unsubscribe_cb(imquic_endpoint *endpoint,
	void (* incoming_unsubscribe)(imquic_connection *conn, uint64_t subscribe_id));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c SUBSCRIBES_BLOCKED request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param subscribes_blocked Pointer to the function that will handle the incoming \c SUBSCRIBES_BLOCKED */
void imquic_set_subscribes_blocked_cb(imquic_endpoint *endpoint,
	void (* subscribes_blocked)(imquic_connection *conn, uint64_t max_subscribe_id));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c SUBSCRIBE_ANNOUNCES request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_subscribe_announces Pointer to the function that will handle the incoming \c SUBSCRIBE_ANNOUNCES */
void imquic_set_incoming_subscribe_announces_cb(imquic_endpoint *endpoint,
	void (* incoming_subscribe_announces)(imquic_connection *conn, imquic_moq_namespace *tns, imquic_moq_auth_info *auth));
/*! \brief Configure the callback function to be notified when an
 * \c SUBSCRIBE_ANNOUNCES we previously sent was accepted
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param subscribe_announces_accepted Pointer to the function that will fire when an \c SUBSCRIBE_ANNOUNCES is accepted */
void imquic_set_subscribe_announces_accepted_cb(imquic_endpoint *endpoint,
	void (* subscribe_announces_accepted)(imquic_connection *conn, imquic_moq_namespace *tns));
/*! \brief Configure the callback function to be notified when an
 * \c SUBSCRIBE_ANNOUNCES we previously sent was rejected with an error
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param subscribe_announces_error Pointer to the function that will fire when an \c SUBSCRIBE_ANNOUNCES is rejected */
void imquic_set_subscribe_announces_error_cb(imquic_endpoint *endpoint,
	void (* subscribe_announces_error)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c UNSUBSCRIBE_ANNOUNCES request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_unsubscribe_announces Pointer to the function that will handle the incoming \c UNSUBSCRIBE_ANNOUNCES */
void imquic_set_incoming_unsubscribe_announces_cb(imquic_endpoint *endpoint,
	void (* incoming_unsubscribe_announces)(imquic_connection *conn, imquic_moq_namespace *tns));
/*! \brief Configure the callback function to be notified when there's
 * an incoming standalone \c FETCH request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_standalone_fetch Pointer to the function that will handle the incoming \c FETCH */
void imquic_set_incoming_standalone_fetch_cb(imquic_endpoint *endpoint,
	void (* incoming_standalone_fetch)(imquic_connection *conn, uint64_t subscribe_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, gboolean descending, imquic_moq_fetch_range *range, imquic_moq_auth_info *auth));
/*! \brief Configure the callback function to be notified when there's
 * an incoming joining \c FETCH request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_joining_fetch Pointer to the function that will handle the incoming \c FETCH */
void imquic_set_incoming_joining_fetch_cb(imquic_endpoint *endpoint,
	void (* incoming_joining_fetch)(imquic_connection *conn, uint64_t subscribe_id, uint64_t joining_subscribe_id,
		uint64_t preceding_group_offset, gboolean descending, imquic_moq_auth_info *auth));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c FETCH_CANCEL request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_fetch_cancel Pointer to the function that will handle the incoming \c FETCH_CANCEL */
void imquic_set_incoming_fetch_cancel_cb(imquic_endpoint *endpoint,
	void (* incoming_fetch_cancel)(imquic_connection *conn, uint64_t subscribe_id));
/*! \brief Configure the callback function to be notified when an
 * \c FETCH we previously sent was accepted
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param fetch_accepted Pointer to the function that will fire when an \c FETCH is accepted */
void imquic_set_fetch_accepted_cb(imquic_endpoint *endpoint,
	void (* fetch_accepted)(imquic_connection *conn, uint64_t subscribe_id, gboolean descending, imquic_moq_position *largest));
/*! \brief Configure the callback function to be notified when an
 * \c FETCH we previously sent was rejected with an error
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param fetch_error Pointer to the function that will fire when an \c FETCH is rejected */
void imquic_set_fetch_error_cb(imquic_endpoint *endpoint,
	void (* fetch_error)(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason));
/*! \brief Configure the callback function to be notified when there's
 * an incoming MoQ object, independently of how it was multiplexed on the wire.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_object Pointer to the function that will handle the incoming MoQ object */
void imquic_set_incoming_object_cb(imquic_endpoint *endpoint,
	void (* incoming_object)(imquic_connection *conn, imquic_moq_object *object));
/*! \brief Configure the callback function to be notified when there's
 * an incoming \c GOAWAY request.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param incoming_goaway Pointer to the function that will handle the incoming \c GOAWAY */
void imquic_set_incoming_goaway_cb(imquic_endpoint *endpoint,
	void (* incoming_goaway)(imquic_connection *conn, const char *uri));
/*! \brief Configure the callback function to be notified when an existing
 * MoQ connection handled by this endpoint has been closed/shut down.
 * @note This is a good place to release the last reference to the connection
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param moq_connection_gone Pointer to the function that will be invoked when a MoQ connection is gone */
void imquic_set_moq_connection_gone_cb(imquic_endpoint *endpoint,
	void (* moq_connection_gone)(imquic_connection *conn));
///@}

/*! \brief Roles that can be specified once connected */
typedef enum imquic_moq_role {
	IMQUIC_MOQ_ENDPOINT,	/* Since -08, there are no roles anymore */
	IMQUIC_MOQ_PUBLISHER,
	IMQUIC_MOQ_SUBSCRIBER,
	IMQUIC_MOQ_PUBSUB
} imquic_moq_role;
/*! \brief Helper function to serialize to string the name of a imquic_moq_role property.
 * @param role The imquic_moq_role property
 * @returns The role name as a string, if valid, or NULL otherwise */
const char *imquic_moq_role_str(imquic_moq_role role);
/*! \brief Method to set the MoQ role on a connection. Must be done as
 * soon as the connection is established, and before sending any MoQ message.
 * A good place to do that is the callback fired when a new connection is available.
 * @note The role can only be set once: it's an error to try and change it later,
 * since the MoQ handshake will already have taken place.
 * @param conn The imquic_connection to set the role on
 * @param role The imquic_moq_role to take
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_set_role(imquic_connection *conn, imquic_moq_role role);
/*! \brief Helper function to get the MoQ role associated with a connection.
 * @param conn The imquic_connection to query
 * @returns The imquic_moq_role value */
imquic_moq_role imquic_moq_get_role(imquic_connection *conn);

/*! \brief Versions that can be negotiated */
typedef enum imquic_moq_version {
	/* Base */
	IMQUIC_MOQ_VERSION_BASE = 0xff000000,
	/* Draft version -03 */
	IMQUIC_MOQ_VERSION_MIN = 0xff000003,
	IMQUIC_MOQ_VERSION_03 = 0xff000003,
	/* Draft version -04 */
	IMQUIC_MOQ_VERSION_04 = 0xff000004,
	/* Draft version -05 */
	IMQUIC_MOQ_VERSION_05 = 0xff000005,
	/* Draft version -06 */
	IMQUIC_MOQ_VERSION_06 = 0xff000006,
	/* Draft version -07 */
	IMQUIC_MOQ_VERSION_07 = 0xff000007,
	/* Draft version -08 */
	IMQUIC_MOQ_VERSION_08 = 0xff000008,
	/* Draft version -09 */
	IMQUIC_MOQ_VERSION_09 = 0xff000009,
	/* Draft version -10 */
	IMQUIC_MOQ_VERSION_10 = 0xff000010,
	IMQUIC_MOQ_VERSION_MAX = IMQUIC_MOQ_VERSION_10,
	/* Any post-v06 version: for client, it means offer all supported versions;
	 * for servers, it means accept the first supported offered version */
	IMQUIC_MOQ_VERSION_ANY = 0xffffffff,
	/* Any pre-v06 version: for client, it means offer all supported versions;
	 * for servers, it means accept the first supported offered version */
	IMQUIC_MOQ_VERSION_ANY_LEGACY = 0xfffffffe,
} imquic_moq_version;
/*! \brief Helper function to serialize to string the name of a imquic_moq_version property.
 * @param version The imquic_moq_version property
 * @returns The version name as a string, if valid, or NULL otherwise */
const char *imquic_moq_version_str(imquic_moq_version version);
/*! \brief Method to set the MoQ version on a connection. Must be done as
 * soon as the connection is established, and before sending any MoQ message.
 * A good place to do that is the callback fired when a new connection is available.
 * @note The version can only be set once: it's an error to try and change it later,
 * since the MoQ handshake will already have taken place.
 * @param conn The imquic_connection to set the version on
 * @param version The imquic_moq_version to use/offer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_set_version(imquic_connection *conn, imquic_moq_version version);
/*! \brief Helper function to get the MoQ version associated with a connection.
 * @param conn The imquic_connection to query
 * @returns The imquic_moq_version value */
imquic_moq_version imquic_moq_get_version(imquic_connection *conn);

/*! \brief Helper function to set the Maximum Subscribe ID a subscriber can send
 * \note If invoked before the MoQ connection setup, it will be put in the
 * setup parameter, otherwise it's sent in a \c MAX_SUBSCRIBE_ID request
 * @param conn The imquic_connection to update
 * @param max_subscribe_id The Maximum Subscribe ID to enforce
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_set_max_subscribe_id(imquic_connection *conn, uint64_t max_subscribe_id);

/** @name Using the MoQ API
 */
///@{
/* Namespaces and subscriptions */
/*! \brief Function to send an \c ANNOUNCE request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to announce
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_announce(imquic_connection *conn, imquic_moq_namespace *tns);
/*! \brief Function to accept an incoming \c ANNOUNCE request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to accept
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_accept_announce(imquic_connection *conn, imquic_moq_namespace *tns);
/*! \brief Function to reject an incoming \c ANNOUNCE request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to reject
 * @param error_code The error code to send back
 * @param reason A string representation of the error, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_reject_announce(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason);
/*! \brief Function to send an \c UNANNOUNCE request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to unannounce
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_unannounce(imquic_connection *conn, imquic_moq_namespace *tns);
/*! \brief Function to send a \c SUBSCRIBE request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id A unique numeric identifier to associate to this subscription
 * @param track_alias A unique numeric identifier to associate to the track in this subscription
 * @param tns The imquic_moq_namespace namespace the track to subscribe to belongs to
 * @param tn The imquic_moq_name track name to subscribe to
 * @param auth The imquic_moq_auth_info authentication info, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth);
/*! \brief Function to accept an incoming \c SUBSCRIBE request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id The unique \c subscribe_id value associated to the subscription to accept
 * @param expires Value of \c expires to send back
 * @param descending Whether objects will be delivered in descending group order
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_accept_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t expires, gboolean descending);
/*! \brief Function to reject an incoming \c SUBSCRIBE request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id The unique \c subscribe_id value associated to the subscription to reject
 * @param error_code The error code to send back
 * @param reason A string representation of the error, if needed
 * @param track_alias The unique \c track_alias value associated to the subscription to reject
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_reject_subscribe(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason, uint64_t track_alias);
/*! \brief Function to send a \c UNSUBSCRIBE request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id The unique \c subscribe_id value associated to the subscription to unsubscribe from
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_unsubscribe(imquic_connection *conn, uint64_t subscribe_id);
/*! \brief Function to send a \c SUBSCRIBE_ANNOUNCES request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace the track to subscribe to belongs to
 * @param auth The imquic_moq_auth_info authentication info, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_subscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns, imquic_moq_auth_info *auth);
/*! \brief Function to accept an incoming \c SUBSCRIBE_ANNOUNCES request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to accept notifications for
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_accept_subscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns);
/*! \brief Function to reject an incoming \c SUBSCRIBE_ANNOUNCES request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to reject notifications for
 * @param error_code The error code to send back
 * @param reason A string representation of the error, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_reject_subscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason);
/*! \brief Function to send a \c UNSUBSCRIBE_ANNOUNCES request
 * @param conn The imquic_connection to send the request on
 * @param tns The imquic_moq_namespace namespace to unsubscribe notifications from
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_unsubscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns);
/*! \brief Function to send a standalone \c FETCH request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id A unique numeric identifier to associate to this subscription
 * @param tns The imquic_moq_namespace namespace the track to fetch to belongs to
 * @param tn The imquic_moq_name track name to fetch to
 * @param descending Whether objects should be fetched in descending group order
 * @param range The range of groups/objects to fetch
 * @param auth The imquic_moq_auth_info authentication info, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_standalone_fetch(imquic_connection *conn, uint64_t subscribe_id,
	imquic_moq_namespace *tns, imquic_moq_name *tn,
	gboolean descending, imquic_moq_fetch_range *range, imquic_moq_auth_info *auth);
/*! \brief Function to send a joining \c FETCH request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id A unique numeric identifier to associate to this subscription
 * @param joining_subscribe_id Existing subscription to join
 * @param preceding_group_offset How many groups to retrieve before the current one
 * @param descending Whether objects should be fetched in descending group order
 * @param auth The imquic_moq_auth_info authentication info, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_joining_fetch(imquic_connection *conn, uint64_t subscribe_id, uint64_t joining_subscribe_id,
	uint64_t preceding_group_offset, gboolean descending, imquic_moq_auth_info *auth);
/*! \brief Function to accept an incoming \c FETCH request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id The unique \c subscribe_id value associated to the subscription to accept
 * @param descending Whether objects will be delivered in descending group order
 * @param largest The largest group/object IDs
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_accept_fetch(imquic_connection *conn, uint64_t subscribe_id, gboolean descending, imquic_moq_position *largest);
/*! \brief Function to reject an incoming \c FETCH request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id The unique \c subscribe_id value associated to the subscription to reject
 * @param error_code The error code to send back
 * @param reason A string representation of the error, if needed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_reject_fetch(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason);
/*! \brief Function to send a \c FETCH_CANCEL request
 * @param conn The imquic_connection to send the request on
 * @param subscribe_id The unique \c subscribe_id value associated to the subscription to cancel_fetch from
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_cancel_fetch(imquic_connection *conn, uint64_t subscribe_id);
/*! \brief Function to send a MoQ object
 * @note Depending on the delivery mode, to close the stream set the
 * \c end_of_stream property to \c TRUE in the object. There's no need to
 * do that when using \c OBJECT_STREAM or \c OBJECT_DATAGRAM . You can
 * also close the stream when you don't have any object to send: just set
 * the relevant properties (e.g., subscribe_id, group_id and subgroup_id)
 * without any payload, and the stack will find the right stream to close it.
 * @param conn The imquic_connection to send the object on
 * @param object The imquic_moq_object object to send, including all relevant identifiers and the payload
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_moq_send_object(imquic_connection *conn, imquic_moq_object *object);
///@}

#endif
