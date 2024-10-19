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

/// struct for passing parameters to the method [`create_custom_document_type_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateCustomDocumentTypeResourceParams {
    /// The <code>CustomDocumentType</code>.
    pub custom_document_type: Option<crate::http::models::CustomDocumentType>,
}

/// struct for passing parameters to the method [`get_custom_document_type_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetCustomDocumentTypeResourceParams {
    /// the name of the reference type
    pub r#type: String,
}

/// struct for typed errors of method [`create_custom_document_type_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateCustomDocumentTypeResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_all_custom_document_type_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAllCustomDocumentTypeResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_custom_document_type_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetCustomDocumentTypeResourceError {
    UnknownValue(serde_json::Value),
}

/// Create type, if it doesn't already exists. Note that new custom document types are  created automatically when you create custom documents, so normally  you do not need to call this method.   Throws HTTP 400 <code>referenceTypeNotAllowed</code> if the name of the type is not allowed.
pub async fn create_custom_document_type_resource(
    configuration: &configuration::Configuration,
    params: CreateCustomDocumentTypeResourceParams,
) -> Result<i32, Error<CreateCustomDocumentTypeResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let custom_document_type = params.custom_document_type;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/documentdeliveries/custom/documenttypes-v1",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&custom_document_type);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateCustomDocumentTypeResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_all_custom_document_type_resource(
    configuration: &configuration::Configuration,
) -> Result<
    Vec<crate::http::models::CustomDocumentType>,
    Error<GetAllCustomDocumentTypeResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/api/warehouse/documentdeliveries/custom/documenttypes-v1",
        local_var_configuration.base_path
    );
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
        let local_var_entity: Option<GetAllCustomDocumentTypeResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_custom_document_type_resource(
    configuration: &configuration::Configuration,
    params: GetCustomDocumentTypeResourceParams,
) -> Result<crate::http::models::CustomDocumentType, Error<GetCustomDocumentTypeResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let r#type = params.r#type;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/api/warehouse/documentdeliveries/custom/documenttypes-v1/{type}", local_var_configuration.base_path, type=crate::http::apis::urlencode(r#type));
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
        let local_var_entity: Option<GetCustomDocumentTypeResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
