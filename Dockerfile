# Use variable base image, such that we can also build for other base images, like alpine.
ARG BASE_IMAGE=debian:stable-slim

FROM golang:1 as build

# Set build environment
ENV CGO_ENABLED=0

# Leverage docker cache for faster build times
# graph command is a workaround because go cmd 
# does not support installing the dependencies 
# isolated from the source code see: https://github.com/golang/go/issues/27719
COPY ./go.mod /irmago/
WORKDIR /irmago
RUN go mod graph | awk '$1 !~ /@/ { print $2 }' | xargs -r go get

# Build irma CLI tool
COPY . /irmago
RUN go build -a -ldflags '-extldflags "-static"' -o "/bin/irma" ./irma

FROM $BASE_IMAGE

# The debian image does not include openssl, so we have to install this first.
RUN if which apt-get &> /dev/null; then apt-get update && apt-get install -y ca-certificates openssl; fi

COPY --from=build /bin/irma /usr/local/bin/irma

# Include schemes in the Docker image to speed up the start-up time.
RUN irma scheme download

ENTRYPOINT ["irma"]
