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

/// struct for passing parameters to the method [`change_manual_ob_value`]
#[derive(Clone, Debug, Default)]
pub struct ChangeManualObValueParams {
    /// Asset number
    pub given_number: String,
    /// asset
    pub asset: Option<crate::http::models::ManualObAsset>,
}

/// struct for passing parameters to the method [`create_assets_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateAssetsResourceParams {
    /// asset
    pub asset: Option<crate::http::models::CreateAssetWrap>,
}

/// struct for passing parameters to the method [`delete_assets_resource`]
#[derive(Clone, Debug, Default)]
pub struct DeleteAssetsResourceParams {
    /// Asset number
    pub given_number: String,
    /// request
    pub request: Option<crate::http::models::DeleteWrap>,
}

/// struct for passing parameters to the method [`depreciate`]
#[derive(Clone, Debug, Default)]
pub struct DepreciateParams {
    /// body
    pub body: Option<crate::http::models::DepreciationWrap>,
}

/// struct for passing parameters to the method [`get_assets_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetAssetsResourceParams {
    /// Asset number
    pub given_number: String,
}

/// struct for passing parameters to the method [`get_deprecation_list`]
#[derive(Clone, Debug, Default)]
pub struct GetDeprecationListParams {
    /// toDate
    pub to_date: String,
}

/// struct for passing parameters to the method [`scrap`]
#[derive(Clone, Debug, Default)]
pub struct ScrapParams {
    /// Asset number
    pub given_number: String,
    /// asset
    pub asset: Option<crate::http::models::ScrapWrap>,
}

/// struct for passing parameters to the method [`sell`]
#[derive(Clone, Debug, Default)]
pub struct SellParams {
    /// Asset number
    pub given_number: String,
    /// asset
    pub asset: Option<crate::http::models::SellWrap>,
}

/// struct for passing parameters to the method [`write_down`]
#[derive(Clone, Debug, Default)]
pub struct WriteDownParams {
    /// Asset number
    pub given_number: String,
    /// asset
    pub asset: Option<crate::http::models::WriteDownWrap>,
}

/// struct for passing parameters to the method [`write_up`]
#[derive(Clone, Debug, Default)]
pub struct WriteUpParams {
    /// Asset number
    pub given_number: String,
    /// asset
    pub asset: Option<crate::http::models::WriteUpWrap>,
}

/// struct for typed errors of method [`change_manual_ob_value`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChangeManualObValueError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`create_assets_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateAssetsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`delete_assets_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeleteAssetsResourceError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`depreciate`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DepreciateError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_assets_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAssetsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_deprecation_list`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetDeprecationListError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`list_assets_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListAssetsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`scrap`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScrapError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`sell`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SellError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`write_down`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WriteDownError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`write_up`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WriteUpError {
    UnknownValue(serde_json::Value),
}

/// The updated asset will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn change_manual_ob_value(
    configuration: &configuration::Configuration,
    params: ChangeManualObValueParams,
) -> Result<crate::http::models::AssetSingle, Error<ChangeManualObValueError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;
    let asset = params.asset;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&asset);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ChangeManualObValueError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The created asset will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn create_assets_resource(
    configuration: &configuration::Configuration,
    params: CreateAssetsResourceParams,
) -> Result<crate::http::models::AssetSingle, Error<CreateAssetsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let asset = params.asset;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/assets/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&asset);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateAssetsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// By specifying a {GivenNumber} in the URL a single &quot;Not active&quot; asset or asset with a type &quot;Not depreciable&quot; can be deleted. By specifying a {GivenNumber} in the URL a single &quot;Active&quot; or &quot;Fully depreciated&quot; assets can be voided and in this case in request body voiddate should be provided, otherwise it will use todays date.
pub async fn delete_assets_resource(
    configuration: &configuration::Configuration,
    params: DeleteAssetsResourceParams,
) -> Result<(), Error<DeleteAssetsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;
    let request = params.request;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::DELETE, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&request);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        Ok(())
    } else {
        let local_var_entity: Option<DeleteAssetsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The created vouchers list will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn depreciate(
    configuration: &configuration::Configuration,
    params: DepreciateParams,
) -> Result<crate::http::models::DepreciationResponseWrap, Error<DepreciateError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let body = params.body;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/assets/depreciate", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&body);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<DepreciateError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_assets_resource(
    configuration: &configuration::Configuration,
    params: GetAssetsResourceParams,
) -> Result<crate::http::models::AssetSingle, Error<GetAssetsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
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
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetAssetsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Retrieves a list of assets to depreciate.
pub async fn get_deprecation_list(
    configuration: &configuration::Configuration,
    params: GetDeprecationListParams,
) -> Result<crate::http::models::ListAssetWrap, Error<GetDeprecationListError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let to_date = params.to_date;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/depreciations/{ToDate}",
        local_var_configuration.base_path,
        ToDate = crate::http::apis::urlencode(to_date)
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
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetDeprecationListError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn list_assets_resource(
    configuration: &configuration::Configuration,
) -> Result<crate::http::models::ListAssetWrap, Error<ListAssetsResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/assets/", local_var_configuration.base_path);
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
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ListAssetsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The updated asset will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn scrap(
    configuration: &configuration::Configuration,
    params: ScrapParams,
) -> Result<crate::http::models::AssetSingle, Error<ScrapError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;
    let asset = params.asset;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/scrap/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&asset);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ScrapError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Partial sell or full sell of an asset.
pub async fn sell(
    configuration: &configuration::Configuration,
    params: SellParams,
) -> Result<crate::http::models::AssetSingle, Error<SellError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;
    let asset = params.asset;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/sell/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&asset);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<SellError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The updated asset will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn write_down(
    configuration: &configuration::Configuration,
    params: WriteDownParams,
) -> Result<crate::http::models::AssetSingle, Error<WriteDownError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;
    let asset = params.asset;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/writedown/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&asset);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<WriteDownError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The updated asset will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn write_up(
    configuration: &configuration::Configuration,
    params: WriteUpParams,
) -> Result<crate::http::models::AssetSingle, Error<WriteUpError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let given_number = params.given_number;
    let asset = params.asset;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/assets/writeup/{GivenNumber}",
        local_var_configuration.base_path,
        GivenNumber = crate::http::apis::urlencode(given_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&asset);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<WriteUpError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
