imquic examples
===============

This folder contains a set of examples aimed at showcasing how you can integrate imquic in applications for different use cases. Notice that they're meant as simple demo examples, and are not strictly speaking representative of the coding style you should adhere to, or indicative of the expected performance of the library.

There are a few different client/server examples showing how you can use imquic for:

* generic QUIC applications (raw QUIC and/or WebTransport);
* native RTP over QUIC (RoQ) support;
* native Media over QUIC (RoQ) support.

You can choose which examples to build by passing arguments to the `./configure` script.

## Echo examples

To build the client/server echo examples, pass `--enable-echo-examples` to the `./configure` script. This will build two command line applications, namely:

* `imquic-echo-server`, a basic QUIC/WebTransport echo server;
* `imquic-echo-client`, a basic QUIC/WebTransport echo client.

Both provide a few configuration options: pass `-h` or `--help` for more information.

This example launches a raw QUIC server (since `-q` is passed), negotiating the `doq` ALPN, listening on port `9000`, using the provided certificate, and saving the shared TLS secrets to the provided `SSLKEYLOGFILE` (e.g., for live debugging of the QUIC traffic via Wireshark):

	./examples/imquic-echo-server -q -a doq -p 9000 -c ../localhost.crt -k ../localhost.key -s ../key_log.log

This has the echo client connect to that server:

	./examples/imquic-echo-client -q -a doq -r 127.0.0.1 -R 9000

This other example launches a WebTransport server (since `-w` is passed) instead:

	./examples/imquic-echo-server -w -p 9000 -c ../localhost.crt -k ../localhost.key -s ../key_log.log

This has the echo client connect to that server:

	./examples/imquic-echo-client -w -r 127.0.0.1 -R 9000

In both cases, the client will then send a single `ciao` buffer on a bidirectional \c STREAM that the server will echo back. Both client and server can be configured to offer both raw QUIC and WebTransport at the same time.

## RTP Over QUIC (RoQ) examples

To build the RTP Over QUIC (RoQ) examples, pass `--enable-roq-examples` to the `./configure` script. This will build two command line applications, namely:

* `imquic-roq-server`, a basic RoQ server, that will just print the flow ID and RTP headers of the incoming packets;
* `imquic-roq-client`, a basic RoQ client, that will listen for RTP packets on some UDP ports, and restream them via QUIC.

Both provide a few configuration options: pass `-h` or `--help` for more information.

This launches the RoQ server on port `9000`, using the provided certificate, and saving the shared TLS secrets to the provided `SSLKEYLOGFILE` (e.g., for live debugging of the QUIC traffic via Wireshark); raw QUIC is used (`-q`), but unlike before the ALPN is omitted, since it will automatically be set by the RoQ stack in the library:

	./examples/imquic-roq-server -q -p 9000 -c ../localhost.crt -k ../localhost.key -s ../key_log.log

This launches the RoQ client to connect to that server, waiting for audio RTP packets on port `15002` (whose flow ID on RoQ will be `0`) and for video RTP packets on port `15004` (whose flow ID on RoQ will be `1`), and using a separate \c STREAM for each RTP packet:

	./examples/imquic-roq-client -q -a 15002 -A 0 -v 15004 -V 1 -r 127.0.0.1 -R 9000 -m streams

Sending RTP traffic to those ports (e.g., from GStreamer, FFmpeg, Janus RTP forwarders or others), will have the RoQ client send them to the RoQ server.

## Media Over QUIC (MoQ) examples

To build the Media Over QUIC (MoQ) examples, pass `--enable-moq-examples` to the `./configure` script. This will build a few command line applications, namely:

* `imquic-moq-pob`, a basic MoQ publisher (basically a clone on `moq-clock` in [moq-rs](https://github.com/kixelated/moq-rs));
* `imquic-moq-sub`, a basic MoQ subscriber (with support for a few different kinds of media);
* `imquic-moq-chat`, a basic MoQ publisher/subscriber that implements the [moq-chat](https://datatracker.ietf.org/doc/draft-frindell-moq-chat/) draft (still WIP);
* `imquic-moq-relay`, a basic MoQ relay.

All provide a few configuration options: pass `-h` or `--help` for more information.

Having a relay available is a prerequisite for testing the client demos. The `imquic-moq-relay` application is a basic (and not very performant) relay implementation with support for most of the MoQ features. This launches a MoQ relay that can be reached both via raw QUIC and WebTransport (`-q -w`), and that only accepts connections negotiating version -07 of the draft (`-M`):

	./examples/imquic-moq-relay -p 9000 -c ../localhost.crt -k ../localhost.key -q -w -M 7 -s ../key_log.log

Assuming a relay (`imquic-moq-relay` or others) is listening on that address, this creates a MoQ publisher using WebTransport (`-w`) that publishes the current time to the `clock` namespace and `now` track; since `-M` is not provided, support for multiple versions of MoQ is offered:

	./examples/imquic-moq-pub -r 127.0.0.1 -R 9000 -w -n clock -N now -w -s ../key_log.log

A MoQ subscriber for that namespace/track (with `-t text` to tell the application to interpret the objects as text) using raw QUIC (`-q`) can be run as following:

	./examples/imquic-moq-sub -r 127.0.0.1 -R 9000 -q -n clock -N now -t text -s ../key_log.log

Assuming [moq-rs](https://github.com/kixelated/moq-rs)'s `moq-pub` application is publishing a video file to a relay, this command will subscribe to the MP4 container video (`-t mp4` will instruct the subscriber to save the objects to the provided file):

	./examples/imquic-moq-sub -r 127.0.0.1 -R 9000 -w -n pippo -N 0.mp4 -t mp4 -o test.mp4

Assuming Meta's [moxygen](https://github.com/facebookexperimental/moxygen) relay is running on that address and that a [moq-encoder-player](https://github.com/facebookexperimental/moq-encoder-player/) instance is publishing audio and video, this creates a MoQ subscriber (on WebTransport) to both tracks that prints the LOC header (`-t loc`) of each incoming object:

	./examples/imquic-moq-sub -r 127.0.0.1 -R 4433 -w -H /moq -n vc -N 12345678-audio -N 12345678-video -a secret -t loc -w -s ../key_log.log