# OpenSrv - MySQL

**Bindings for emulating a MySQL/MariaDB server.**

When developing new databases or caching layers, it can be immensely useful to test your system
using existing applications. However, this often requires significant work modifying
applications to use your database over the existing ones. This crate solves that problem by
acting as a MySQL server, and delegating operations such as querying and query execution to
user-defined logic.

## Usage

To start, implement `AsyncMysqlShim` for your backend, and create a `AsyncMysqlIntermediary` over an
instance of your backend and a connection stream. The appropriate methods will be called on
your backend whenever a client issues a `QUERY`, `PREPARE`, or `EXECUTE` command, and you will
have a chance to respond appropriately. For example, to write a shim that always responds to
all commands with a "no results" reply:

```rust
use std::io;
use tokio::io::AsyncWrite;

use opensrv_mysql::*;
use tokio::net::TcpListener;

struct Backend;

#[async_trait::async_trait]
impl<W: AsyncWrite + Send + Unpin> AsyncMysqlShim<W> for Backend {
    type Error = io::Error;

    async fn on_prepare<'a>(
        &'a mut self,
        _: &'a [u8],
        info: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        info.reply(42, &[], &[]).await
    }

    async fn on_execute<'a>(
        &'a mut self,
        _: u32,
        _: opensrv_mysql::ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        results.completed(OkResponse::default()).await
    }

    async fn on_close(&mut self, _: u32) {}

    async fn on_query<'a>(
        &'a mut self,
        sql: &'a [u8],
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        println!("execute sql {:?}", sql);
        results.start(&[]).await?.finish().await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:3306").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let (r, w) = stream.into_split();
        tokio::spawn(async move { AsyncMysqlIntermediary::run_on(Backend, r, w).await });
    }
}
```

This example can be exected with:

```
cargo run --example=serve_one
```

More examples can be found [here](examples).

## Getting help

Submit [issues](https://github.com/datafuselabs/opensrv/issues/new/choose) for bug report or asking questions in [discussion](https://github.com/datafuselabs/opensrv/discussions/new?category=q-a).

## Credits

This project is a branch of [jonhoo/msql-srv](https://github.com/jonhoo/msql-srv) and focuses on providing asynchronous support.

## Classic query bindings

The legacy backend parameter API is fallible: use `ParamParser::parse()?`,
not an iterator over untrusted packets. `Params` and the unchecked
`IntoIterator` implementation have been removed.

Query attributes are **off by default**, including when a backend adds the
capability manually without installing `query_attributes_admission()`.
An opting-in shim must implement `on_query_bindings` and
`on_execute_bindings` and issue a real, retained allocation permit. The
default callbacks reject the new envelope rather than discard attributes.
`ParsedBindings` exposes ordered raw slots and the SQL suffix; names/types
are interleaved in the wire packet. `bind_placeholders()` returns the first
actual statement parameter count with its own retained allocation permit.
Attribute names and values are never cached in prepared statement state.

`Packet::owned_range()` shares the actual Bytes allocation, including while
the reader polls the next command. Dispatch-issued envelopes also expose
`packet_owner()` and checked `packet_range()` for zero-copy downstream
command retention (placeholder long data has its own StatementData owner).
This does not claim admission coverage for
the pre-existing receive/decompression buffers. It does not install
`mysql_query_attribute_string` or a component ABI.

## License

Licensed under <a href="./LICENSE">Apache License, Version 2.0</a>.
