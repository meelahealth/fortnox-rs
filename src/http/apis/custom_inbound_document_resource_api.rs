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

/// struct for passing parameters to the method [`get_custom_inbound_document_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetCustomInboundDocumentResourceParams {
    /// Document type.
    pub r#type: String,
    /// Document id.
    pub id: String,
}

/// struct for passing parameters to the method [`release_custom_inbound_document_resource`]
#[derive(Clone, Debug, Default)]
pub struct ReleaseCustomInboundDocumentResourceParams {
    /// document type
    pub r#type: String,
    /// document id
    pub id: String,
}

/// struct for passing parameters to the method [`save_custom_inbound_document_resource`]
#[derive(Clone, Debug, Default)]
pub struct SaveCustomInboundDocumentResourceParams {
    /// min 1 character, max 25 characters, may contain letters A-Z, digits 0-9, underscore (_), and dash (-), type is case-insensitive  <blockquote><pre>       Type is a custom name/reference of the document that will be used to reference the document type <br>       * If type is not known, it will be registered as belonging to the INBOUND category. <br>       * If type is an existing custom document type of category OUTBOUND an error is thrown. <br>       * If type is invalid an error is thrown. <br>  </pre></blockquote>
    pub r#type: String,
    /// min 1 character, max 25 characters, may only contain digits 0-9
    pub id: String,
    /// the <code>CustomInboundDocument</code> to create
    pub document: Option<crate::http::models::CustomInboundDocument>,
}

/// struct for passing parameters to the method [`void_document_custom_inbound_document_resource`]
#[derive(Clone, Debug, Default)]
pub struct VoidDocumentCustomInboundDocumentResourceParams {
    /// document type
    pub r#type: String,
    /// document id
    pub id: String,
    /// true if the document should be voided even if the document has connected outbounds, defaults to false.
    pub force: Option<bool>,
}

/// struct for typed errors of method [`get_custom_inbound_document_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetCustomInboundDocumentResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`release_custom_inbound_document_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReleaseCustomInboundDocumentResourceError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`save_custom_inbound_document_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SaveCustomInboundDocumentResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`void_document_custom_inbound_document_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VoidDocumentCustomInboundDocumentResourceError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

pub async fn get_custom_inbound_document_resource(
    configuration: &configuration::Configuration,
    params: GetCustomInboundDocumentResourceParams,
) -> Result<crate::http::models::CustomInboundDocument, Error<GetCustomInboundDocumentResourceError>>
{
    let local_var_configuration = configuration;

    // unbox the parameters
    let r#type = params.r#type;
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/api/warehouse/documentdeliveries/custom/inbound-v1/{type}/{id}", local_var_configuration.base_path, type=crate::http::apis::urlencode(r#type), id=crate::http::apis::urlencode(id));
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetCustomInboundDocumentResourceError> =
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
pub async fn release_custom_inbound_document_resource(
    configuration: &configuration::Configuration,
    params: ReleaseCustomInboundDocumentResourceParams,
) -> Result<(), Error<ReleaseCustomInboundDocumentResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let r#type = params.r#type;
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/api/warehouse/documentdeliveries/custom/inbound-v1/{type}/{id}/release", local_var_configuration.base_path, type=crate::http::apis::urlencode(r#type), id=crate::http::apis::urlencode(id));
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
        let local_var_entity: Option<ReleaseCustomInboundDocumentResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn save_custom_inbound_document_resource(
    configuration: &configuration::Configuration,
    params: SaveCustomInboundDocumentResourceParams,
) -> Result<crate::http::models::CustomInboundDocument, Error<SaveCustomInboundDocumentResourceError>>
{
    let local_var_configuration = configuration;

    // unbox the parameters
    let r#type = params.r#type;
    let id = params.id;
    let document = params.document;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/api/warehouse/documentdeliveries/custom/inbound-v1/{type}/{id}", local_var_configuration.base_path, type=crate::http::apis::urlencode(r#type), id=crate::http::apis::urlencode(id));
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&document);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<SaveCustomInboundDocumentResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Voiding a document will undo the possible stock changes that the document had made,  note that the document and the transactions created are not deleted. Some limitations apply, see below.
pub async fn void_document_custom_inbound_document_resource(
    configuration: &configuration::Configuration,
    params: VoidDocumentCustomInboundDocumentResourceParams,
) -> Result<(), Error<VoidDocumentCustomInboundDocumentResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let r#type = params.r#type;
    let id = params.id;
    let force = params.force;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/api/warehouse/documentdeliveries/custom/inbound-v1/{type}/{id}/void", local_var_configuration.base_path, type=crate::http::apis::urlencode(r#type), id=crate::http::apis::urlencode(id));
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = force {
        local_var_req_builder =
            local_var_req_builder.query(&[("force", &local_var_str.to_string())]);
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
        Ok(())
    } else {
        let local_var_entity: Option<VoidDocumentCustomInboundDocumentResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
