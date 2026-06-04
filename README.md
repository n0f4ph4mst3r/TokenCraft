# TokenCraft

## Description

SSO for providing secure user authentication, access/refresh token management, and role-based access control.

## System requirements

You need to have [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) installed in order to build and run the project. No additional tools required.

## How to run with Docker

Define environment variables. You can copy environment from [example](https://github.com/n0f4ph4mst3r/TokenCraft/blob/main/.env.sample)

    cp .env.sample .env

Perform

	sudo docker-compose up

The service will start according to your configuration.

## How to run manually

### Tools

To develop the app manually, you need the following tools installed:

- [Go](https://go.dev/) (version 1.25.4 or newer)

- [Postgres](https://www.postgresql.org/) and [Redis](https://redis.io/) databases (you can run them via Docker Compose)

### Start the dev DB

If you don’t have Postgres or Redis installed locally, you can start them with Docker Compose:

    sudo docker-compose -f docker-compose.yml up postgres redis

This will start local Postgres and Redis instances.

### Start the server

Run following command:

    go run ./cmd/main.go

This will compile and start the authentication service. The gRPC API will be accessible via your [config](https://github.com/n0f4ph4mst3r/TokenCraft/blob/main/config/sample.yaml) and [env](https://github.com/n0f4ph4mst3r/TokenCraft/blob/main/.env.sample) settings. 

### Usage

See the proto definition for available endpoints. To ensure secure token signing, this service utilizes the RS256 algorithm, which requires an RSA key pair; you must generate a 2048-bit private key using this command:

    openssl genrsa -out private.pem 2048

and its corresponding public key for your services with:

    openssl rsa -in private.pem -pubout -out public.pem