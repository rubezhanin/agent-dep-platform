//! Catalog endpoint stub. The 2.0.0 server does not
//! expose a `GET /v1/catalog` route; the catalog
//! snapshot list lives in `handlers::list_systems`.
//! This module is a placeholder for 2.0.x where the
//! catalog will be uploaded via `POST /v1/catalog`
//! and stored as a v2 `Source`.

pub fn _placeholder() {}
