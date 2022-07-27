FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake

COPY . /repo
WORKDIR /repo/build
RUN cmake ..
RUN make -j8

FROM ubuntu:20.04 as package
COPY --from=builder /repo/build /build
ENV LD_LIBRARY_PATH=/build/lib
