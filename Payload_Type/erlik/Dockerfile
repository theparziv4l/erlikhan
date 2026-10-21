FROM itsafeaturemythic/mythic_go_base:latest

# Pipeline tools: signing, packing, container formats, symbol strip.
# UPX left the Debian repos, so it comes from its GitHub release.
# zig cross-compiles the native C agent (compiler=native).
RUN apt-get update && apt-get install -y --no-install-recommends \
	osslsigncode \
	genisoimage \
	dosfstools \
	mtools \
	p7zip-full \
	wixl \
	binutils \
	xz-utils \
	&& rm -rf /var/lib/apt/lists/* \
	&& curl -sL -o /tmp/upx.tar.xz https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz \
	&& tar -xJf /tmp/upx.tar.xz -C /tmp \
	&& mv /tmp/upx-5.2.1-amd64_linux/upx /usr/local/bin/upx \
	&& rm -rf /tmp/upx.tar.xz /tmp/upx-5.2.1-amd64_linux \
	&& upx --version \
	&& curl -sL -o /tmp/zig.tar.xz https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz \
	&& tar -xJf /tmp/zig.tar.xz -C /opt \
	&& ln -s /opt/zig-linux-x86_64-0.14.0/zig /usr/local/bin/zig \
	&& rm -rf /tmp/zig.tar.xz \
	&& zig version

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

CMD make run
