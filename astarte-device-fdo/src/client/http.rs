// This file is part of Astarte.
//
// Copyright 2025 SECO Mind Srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use std::future::Future;
use std::marker::PhantomData;
use std::task::Poll;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::{Message, Protver, PROTOCOL_VERSION};
use astarte_fdo_protocol::Error;
use pin_project_lite::pin_project;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Method;
use tower_service::Service;
use tracing::error;
use url::Url;

const MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE: HeaderName = HeaderName::from_static("message-type");

/// Client for the HTTP or HTTPS transport protocol
#[derive(Debug, Clone)]
pub(crate) struct HttpService<S> {
    base_url: Url,
    protocol_version: Protver,
    inner: S,
    buf: Vec<u8>,
}

impl<S> HttpService<S> {
    fn new(base_url: Url, inner: S) -> Self {
        Self {
            base_url,
            protocol_version: PROTOCOL_VERSION,
            inner,
            buf: Vec::new(),
        }
    }

    fn make_url<T>(&self) -> Result<Url, Error>
    where
        T: Message,
    {
        self.base_url
            .join(&format!(
                "/fdo/{}/msg/{}",
                self.protocol_version,
                T::MSG_TYPE
            ))
            .map_err(|err| {
                error!(error = %err, "couldn't parse URL");

                Error::new(ErrorKind::Invalid, "url")
            })
    }

    // TODO: this could receive the body directly
    fn create_req<M>(&mut self, msg: &M) -> Result<reqwest::Request, Error>
    where
        M: Message,
    {
        self.buf.clear();
        msg.encode(&mut self.buf)?;

        let url = self.make_url::<M>()?;
        let mut req = reqwest::Request::new(Method::POST, url);
        req.body_mut().replace(self.buf.clone().into());

        req.headers_mut().insert(MESSAGE_TYPE, M::MSG_TYPE.into());

        Ok(req)
    }
}

impl<M, S> Service<&M> for HttpService<S>
where
    S: Service<reqwest::Request>,
    S::Error: Display,
    M: Message,
{
    type Response = S::Response;

    type Error = Error;

    type Future = HttpFuture<S>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|error| {
            error!(%error, "HTTP service not ready ");

            Error::new(ErrorKind::Io, "service not ready")
        })
    }

    fn call(&mut self, req: &M) -> Self::Future {
        match self.create_req(req) {
            Ok(req) => HttpFuture::new(self.inner.call(req)),
            Err(err) => HttpFuture::with_err(err),
        }
    }
}

pin_project! {
    #[project = HttpFutureProj]
    pub(crate) enum HttpFuture<S>
    where
            S: Service<reqwest::Request>
    {
            Err { err: Option<Error> },
            Future {
              #[pin]
              future: S::Future,
              _marker: PhantomData<S>
            }
    }
}

impl<S> HttpFuture<S>
where
    S: Service<reqwest::Request>,
{
    fn new(future: S::Future) -> Self {
        Self::Future {
            future,
            _marker: PhantomData,
        }
    }

    fn with_err(err: Error) -> Self {
        Self::Err { err: Some(err) }
    }
}

impl<S> Future for HttpFuture<S>
where
    S: Service<reqwest::Request>,
    S::Error: Display,
{
    type Output = Result<S::Response, Error>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let future = match this {
            HttpFutureProj::Err { err } => {
                let err = err.take().unwrap_or(Error::new(
                    ErrorKind::Invalid,
                    "future polled after completion",
                ));

                return Poll::Ready(Err(err));
            }
            HttpFutureProj::Future { future, _marker } => future,
        };

        let res = futures_util::ready!(future.poll(cx)).map_err(|error| {
            error!(%error, "HTTP requst failed");

            Error::new(ErrorKind::Io, "HTTP request failed")
        });

        Poll::Ready(res)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use astarte_fdo_protocol::v101::di::done::Done;
    use astarte_fdo_protocol::v101::di::set_hmac::SetHmac;
    use astarte_fdo_protocol::v101::hash_hmac::HMac;
    use astarte_fdo_protocol::v101::to1::hello_rv::HelloRv;
    use pretty_assertions::assert_eq;
    use tokio_test::assert_ready;

    use super::*;

    pub(crate) fn from_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        assert!(hex.is_ascii());

        hex.as_bytes()
            .chunks_exact(2)
            .map(|str| {
                let str = str::from_utf8(str).expect("should be hex");

                u8::from_str_radix(str, 16).expect("should be hex")
            })
            .collect()
    }

    #[test]
    fn make_url() {
        let client = HttpService::new("http://example.com".parse().unwrap(), ());

        let url = client.make_url::<HelloRv>().unwrap();

        let exp = "http://example.com/fdo/101/msg/30".parse().unwrap();
        assert_eq!(url, exp);
    }

    #[tokio::test]
    async fn make_req() {
        let (mut service, mut handle) = tower_test::mock::spawn_with(|mock| {
            HttpService::new("http://example.com".parse().unwrap(), mock)
        });

        assert_ready!(service.poll_ready::<&SetHmac>()).unwrap();

        let msg = SetHmac {
            hmac: HMac::with_sha256(Cow::Owned(serde_bytes::ByteBuf::from(from_hex(
                "2f6e3bbedeca49da8645575d195afc2d6ab29c136abd862ec5af47854bc1d47d",
            ))))
            .unwrap(),
        };

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let url = "https://example.com/fdo/msg/10".parse().unwrap();
        let mut req = reqwest::Request::new(Method::POST, url);
        req.body_mut().replace(buf.clone().into());
        req.headers_mut().insert(MESSAGE_TYPE, 10.into());

        let (exp, resp) = handle.next_request().await.unwrap();
        let body = exp.body().unwrap();
        assert_eq!(body.as_bytes().unwrap(), buf);

        buf.clear();
        ciborium::into_writer(&Done, &mut buf).unwrap();
        resp.send_response(buf);

        let response = service.call(&msg);
    }
}
