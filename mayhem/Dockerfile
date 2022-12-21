FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_cstr_isvalid.cpp -fsanitize=fuzzer,address -I /repo/src/util/ -L /repo/build/lib/ -lepanet2 -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/build /build
COPY --from=builder /fuzz /fuzz_cstr_isvalid
ENV LD_LIBRARY_PATH=/build/lib
