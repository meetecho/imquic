imquic
======

imquic is an open source QUIC library designed and developed by [Meetecho](https://www.meetecho.com) for the specific purpose of experimenting with QUIC-based multimedia applications. While it can be used as a generic QUIC (and WebTransport) library, it also comes with experimental native RTP Over QUIC (RoQ) and Media Over QUIC (MoQ) support. At the time of writing, there's no support for HTTP/3 beyond the simple establishment of WebTransport connections. The QUIC foundation is provided by [picoquic](https://github.com/private-octopus/picoquic).

For more information and documentations, make sure you pay the [project website](https://imquic.conf.meetecho.com) a visit!

> **Note well:** in its current stage, the library should be considered at an **alpha** stage, and very experimental. It is currently being used by Meetecho for prototyping RoQ and MoQ demos in local and controlled environments, and will probably not always work as expected in more challenging network scenarios.

## Dependencies

To compile imquic, you'll need to satisfy the following dependencies:

* [GLib](https://docs.gtk.org/glib/)
* [pkg-config](http://www.freedesktop.org/wiki/Software/pkg-config/)
* [picoquic](https://github.com/private-octopus/picoquic) (see instructions below)
* [Jansson](https://github.com/akheron/jansson) (optional; QLOG support)

You'll need to install picoquic in the root folder of the repo, as that's where the configure script will look for it. Besides, you'll need to tell cmake to build picotls too, and build everything with `-fPIC` support, otherwise trying to use it within the context of a shared library like imquic will not work. You can use the following steps to install the dependency:

	git clone https://github.com/private-octopus/picoquic
	cd picoquic
	cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DPICOQUIC_FETCH_PTLS=Y .
	make -j$(nproc)

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

If you're interested in QLOG support, add `--enable-qlog` when launching the `configure` script. Notice that this will require [Jansson](https://github.com/akheron/jansson). Also notice that this is only needed for producing QLOG files of the HTTP/3, RoQ and MoQ "layers": QLOG support for the QUIC stack is supported out of the box by picoquic itself.

You can build some demo applications by adding `--enable-echo-examples` (basic QUIC/WebTransport client/server demos), `--enable-roq-examples` (RoQ demos) and `--enable-moq-examples` (MoQ demos).

To build the documentation, add `--enable-docs`.

## Examples

To learn more about the demo examples, refer to the related [README.md](examples/README.md).

## Help us!
Any thought, feedback or (hopefully not!) insult is welcome!

Developed by [@meetecho](https://github.com/meetecho)
