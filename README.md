imquic
======

imquic is an open source QUIC library designed and developed by [Meetecho](https://www.meetecho.com) for the specific purpose of experimenting with QUIC-based multimedia applications. While it can be used as a generic QUIC (and WebTransport) library, it also comes with experimental native RTP Over QUIC (RoQ) and Media Over QUIC (MoQ) support. At the time of writing, there's no support for HTTP/3 beyond the simple establishment of WebTransport connections.

For more information and documentations, make sure you pay the [project website](https://imquic.conf.meetecho.com) a visit!

> **Note well:** in its current stage, the library should be considered at an **alpha** stage, and very experimental due to its lack of support for some QUIC stack functionality. It is currently being used by Meetecho for prototyping RoQ and MoQ demos in local and controlled environments, and will probably not always work as expected in more challenging network scenarios.

## Dependencies

To compile imquic, you'll need to satisfy the following dependencies:

* [GLib](https://docs.gtk.org/glib/)
* [pkg-config](http://www.freedesktop.org/wiki/Software/pkg-config/)
* [quictls](https://quictls.github.io/) (QUIC TLS)
* [Jansson](https://github.com/akheron/jansson) (optional; QLOG support)

> **Note:** You can also use BoringSSL, instead of quictls, by passing `--enable-boringssl=</path/to/boringssl>`, albeit without early-data support. If BoringSSL is installed in `/opt/boringssl`, the configure script will expect header files in `/opt/boringssl/include` and shared (not static) objects in `/opt/boringssl/lib64`. You'll then need to manually export `LD_LIBRARY_PATH` to the path where BoringSSL shared objects are, when using an application that's linked to the library.

Should you be interested in building the imquic documentation as well (public and internal), you'll need some additional tools too:

* [Doxygen](https://www.doxygen.org)
* [Graphviz](https://www.graphviz.org/)

Notice that, at the time of writing, only Linux is supported as a target, but the library should compile on macOS as well. Both macOS and Windows, as well as other platforms, are planned as a target in future releases.

## Compile

Once you have installed all the dependencies, just use:

	sh autogen.sh

to generate the configure file. After that, configure and compile as usual to start the whole compilation process:

	./configure --prefix=/usr
	make
	make install

Note that the configure script uses `pkg-config` to look for quictls by using the `openssl+quictls` name, which is how it's packaged in some repositories to avoid conflicts with OpenSSL. In case that doesn't work for you, you can use the `QUICTLS_CFLAGS` and `QUICTLS_LIBS` environment variables to specify the include and lib directory of the library when launching the configure script, e.g.

	QUICTLS_CFLAGS="-I/opt/quictls/include/" \
	QUICTLS_LIBS="-L/opt/quictls/lib64/ -lssl -lcrypto" \
	./configure [..]

Should that still result in compilation issues, you can try adding the path to the quictls library to ld, which is what the above mentioned repositories do, e.g.

	echo "/opt/quictls/lib64" > /etc/ld.so.conf.d/quictls-x86_64.conf
	ldconfig

If you're interested in QLOG support, add `--enable-qlog` when launching the `configure` script. Notice that this will require [Jansson](https://github.com/akheron/jansson).

You can build some demo applications by adding `--enable-echo-examples` (basic QUIC/WebTransport client/server demos), `--enable-roq-examples` (RoQ demos) and `--enable-moq-examples` (MoQ demos).

To build the documentation, add `--enable-docs`.

## Examples

To learn more about the demo examples, refer to the related [README.md](examples/README.md).

## Help us!
Any thought, feedback or (hopefully not!) insult is welcome!

Developed by [@meetecho](https://github.com/meetecho)
