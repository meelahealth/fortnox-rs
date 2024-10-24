/*
 * # Documentation   The Fortnox API is organized around REST. This means that we’ve designed it to have resource-oriented URLs and be as predictable as possible for you as developer.  It also means that we use HTTP status codes when something goes wrong and HTTP verbs understod by many API clients around the web.  We use a modified version of OAuth2 for authentication to offer a secure way for both you and our users to interact.  The API is generally built to support both XML and JSON but in this documentation all the examples will be in JSON.  We encourage you to read all the articles in the [general information section](https://developer.fortnox.se/general/)</a> first, before going forward and learning about the different resources.  This to ensure you get an understanding of some of the shared components of the API such as parameters and error handling.  ## Rate limits  The limit is 4 requests per second per access-token. This equals to a bit more than 200 requests per minute.  [Read more about this here.](https://developer.fortnox.se/general/regarding-fortnox-api-rate-limits/)  ## Query parameters  Use query parameters with the ?-character and separate parameters with the &-character.   **Example:**  GET - https://api.fortnox.se/3/invoices?accountnumberfrom=3000&accountnumberto=4000 Read more about our parameters [here](https://developer.fortnox.se/general/parameters/)   Search the documentation using the search field in the top left corner.
 *
 * The version of the OpenAPI document: 1.0.0
 *
 * Generated by: https://openapi-generator.tech
 */

use reqwest;

use super::{configuration, Error};
use crate::http::apis::ResponseContent;

/// struct for passing parameters to the method [`completed`]
#[derive(Clone, Debug, Default)]
pub struct CompletedParams {
    /// Incoming goods document id.
    pub id: i64,
    /// Date for bookkeeping in format `\"YYYY-MM-DD\"`. Must be between document's release date (inclusive) and today's date (inclusive).
    pub booking_date: Option<String>,
}

/// struct for passing parameters to the method [`create_incoming_goods_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateIncomingGoodsResourceParams {
    /// The <code>IncomingGoods</code> document.
    pub incoming_goods: Option<crate::http::models::IncomingGoods>,
}

/// struct for passing parameters to the method [`get_all_incoming_goods_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetAllIncomingGoodsResourceParams {
    /// `true` to include only released documents.  `false` to include only non-released documents.
    pub released: Option<bool>,
    /// `true` to include only completed documents.  `false` to include only non-completed documents.
    pub completed: Option<bool>,
    /// `true` to include only voided documents.  `false` to include only non-voided documents.
    pub voided: Option<bool>,
    /// Include only documents with the given `supplierNumber`.
    pub supplier_number: Option<String>,
    /// Include only documents with the given `itemId`.
    pub item_id: Option<String>,
    /// Include only documents where `note`-field contains the given text (case-insensitive).
    pub note: Option<String>,
    /// Include only documents where `deliveryNote`-field contains the given text (case-insensitive).
    pub delivery_note: Option<String>,
    /// Include only documents where `id` or `deliveryNote`-field contains the given text (case-insensitive).
    pub q: Option<String>,
}

/// struct for passing parameters to the method [`get_incoming_goods_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetIncomingGoodsResourceParams {
    /// Incoming goods document id.
    pub id: i64,
    /// This Supplier Invoice id will be excluded when calculating the takenQuantity.
    pub ignore_supplier_invoice_id: Option<i64>,
}

/// struct for passing parameters to the method [`release_incoming_goods_resource`]
#[derive(Clone, Debug, Default)]
pub struct ReleaseIncomingGoodsResourceParams {
    /// Incoming goods document id.
    pub id: i64,
}

/// struct for passing parameters to the method [`save_incoming_goods_resource`]
#[derive(Clone, Debug, Default)]
pub struct SaveIncomingGoodsResourceParams {
    /// Incoming goods document id.
    pub id: i64,
    /// The <code>IncomingGoods</code> document.
    pub incoming_goods: Option<crate::http::models::IncomingGoods>,
}

/// struct for passing parameters to the method [`void_document_incoming_goods_resource`]
#[derive(Clone, Debug, Default)]
pub struct VoidDocumentIncomingGoodsResourceParams {
    /// Incoming goods document id.
    pub id: i64,
}

/// struct for typed errors of method [`completed`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CompletedError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`create_incoming_goods_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateIncomingGoodsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_all_incoming_goods_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAllIncomingGoodsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_incoming_goods_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetIncomingGoodsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`release_incoming_goods_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReleaseIncomingGoodsResourceError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`save_incoming_goods_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SaveIncomingGoodsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`void_document_incoming_goods_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VoidDocumentIncomingGoodsResourceError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// Mark a released Incoming Goods document as Completed.  Bookkeeping will be finalized.  A Completed Incoming Goods document cannot be matched against  any more Supplier Invoices.
pub async fn completed(
    configuration: &configuration::Configuration,
    params: CompletedParams,
) -> Result<(), Error<CompletedError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;
    let booking_date = params.booking_date;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/{id}/completed",
        local_var_configuration.base_path,
        id = id
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&booking_date);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        Ok(())
    } else {
        let local_var_entity: Option<CompletedError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn create_incoming_goods_resource(
    configuration: &configuration::Configuration,
    params: CreateIncomingGoodsResourceParams,
) -> Result<crate::http::models::IncomingGoods, Error<CreateIncomingGoodsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let incoming_goods = params.incoming_goods;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&incoming_goods);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateIncomingGoodsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>      List incoming goods documents matching the given parameters.  </p>  <p>      Sortable fields:      <code>id</code>,      <code>has_delivery_note</code>,      <code>delivery_note_id</code>,      <code>supplier_number</code>,      <code>date</code>  </p>
pub async fn get_all_incoming_goods_resource(
    configuration: &configuration::Configuration,
    params: GetAllIncomingGoodsResourceParams,
) -> Result<Vec<crate::http::models::IncomingGoodsListRow>, Error<GetAllIncomingGoodsResourceError>>
{
    let local_var_configuration = configuration;

    // unbox the parameters
    let released = params.released;
    let completed = params.completed;
    let voided = params.voided;
    let supplier_number = params.supplier_number;
    let item_id = params.item_id;
    let note = params.note;
    let delivery_note = params.delivery_note;
    let q = params.q;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = released {
        local_var_req_builder =
            local_var_req_builder.query(&[("released", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = completed {
        local_var_req_builder =
            local_var_req_builder.query(&[("completed", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = voided {
        local_var_req_builder =
            local_var_req_builder.query(&[("voided", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = supplier_number {
        local_var_req_builder =
            local_var_req_builder.query(&[("supplierNumber", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = item_id {
        local_var_req_builder =
            local_var_req_builder.query(&[("itemId", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = note {
        local_var_req_builder =
            local_var_req_builder.query(&[("note", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = delivery_note {
        local_var_req_builder =
            local_var_req_builder.query(&[("deliveryNote", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = q {
        local_var_req_builder = local_var_req_builder.query(&[("q", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetAllIncomingGoodsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_incoming_goods_resource(
    configuration: &configuration::Configuration,
    params: GetIncomingGoodsResourceParams,
) -> Result<crate::http::models::IncomingGoods, Error<GetIncomingGoodsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;
    let ignore_supplier_invoice_id = params.ignore_supplier_invoice_id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/{id}",
        local_var_configuration.base_path,
        id = id
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = ignore_supplier_invoice_id {
        local_var_req_builder =
            local_var_req_builder.query(&[("ignoreSupplierInvoiceId", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetIncomingGoodsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The document will be locked and bookkept.  The inbound deliveries will affect available stock.
pub async fn release_incoming_goods_resource(
    configuration: &configuration::Configuration,
    params: ReleaseIncomingGoodsResourceParams,
) -> Result<(), Error<ReleaseIncomingGoodsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/{id}/release",
        local_var_configuration.base_path,
        id = id
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        Ok(())
    } else {
        let local_var_entity: Option<ReleaseIncomingGoodsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn save_incoming_goods_resource(
    configuration: &configuration::Configuration,
    params: SaveIncomingGoodsResourceParams,
) -> Result<crate::http::models::IncomingGoods, Error<SaveIncomingGoodsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;
    let incoming_goods = params.incoming_goods;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/{id}",
        local_var_configuration.base_path,
        id = id
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&incoming_goods);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<SaveIncomingGoodsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Void a document.  If an Incoming Goods document has been Completed, or matched against  Supplier Invoice, it cannot be voided.
pub async fn void_document_incoming_goods_resource(
    configuration: &configuration::Configuration,
    params: VoidDocumentIncomingGoodsResourceParams,
) -> Result<(), Error<VoidDocumentIncomingGoodsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/incominggoods-v1/{id}/void",
        local_var_configuration.base_path,
        id = id
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        Ok(())
    } else {
        let local_var_entity: Option<VoidDocumentIncomingGoodsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
