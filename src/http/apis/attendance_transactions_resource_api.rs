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

/// struct for passing parameters to the method [`create_attendance_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateAttendanceTransactionsResourceParams {
    /// attendance transaction to create
    pub attendance_transaction: Option<crate::http::models::AttendanceTransactionWrap>,
}

/// struct for passing parameters to the method [`get_attendance_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetAttendanceTransactionsResourceParams {
    /// identifies the transaction
    pub id: String,
}

/// struct for passing parameters to the method [`list_attendance_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct ListAttendanceTransactionsResourceParams {
    /// filter by employee id
    pub employeeid: Option<String>,
    /// filter by date
    pub date: Option<String>,
}

/// struct for passing parameters to the method [`update_attendance_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct UpdateAttendanceTransactionsResourceParams {
    /// identifies the transaction
    pub id: String,
    /// to update
    pub attendance_transaction: Option<crate::http::models::AttendanceTransactionWrap>,
}

/// struct for typed errors of method [`create_attendance_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateAttendanceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_attendance_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAttendanceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`list_attendance_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListAttendanceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`update_attendance_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateAttendanceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

pub async fn create_attendance_transactions_resource(
    configuration: &configuration::Configuration,
    params: CreateAttendanceTransactionsResourceParams,
) -> Result<
    crate::http::models::AttendanceTransactionWrap,
    Error<CreateAttendanceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let attendance_transaction = params.attendance_transaction;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/attendancetransactions",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&attendance_transaction);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateAttendanceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Retrieves a specific transaction
pub async fn get_attendance_transactions_resource(
    configuration: &configuration::Configuration,
    params: GetAttendanceTransactionsResourceParams,
) -> Result<
    crate::http::models::AttendanceTransactionWrap,
    Error<GetAttendanceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/attendancetransactions/{id}",
        local_var_configuration.base_path,
        id = crate::http::apis::urlencode(id)
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
        let local_var_entity: Option<GetAttendanceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Supports query-string parameters <strong>employeeid</strong> and <strong>date</strong> for filtering the result.
pub async fn list_attendance_transactions_resource(
    configuration: &configuration::Configuration,
    params: ListAttendanceTransactionsResourceParams,
) -> Result<
    crate::http::models::AttendanceTransactionListItemList,
    Error<ListAttendanceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let employeeid = params.employeeid;
    let date = params.date;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/attendancetransactions",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = employeeid {
        local_var_req_builder =
            local_var_req_builder.query(&[("employeeid", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = date {
        local_var_req_builder =
            local_var_req_builder.query(&[("date", &local_var_str.to_string())]);
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
        let local_var_entity: Option<ListAttendanceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn update_attendance_transactions_resource(
    configuration: &configuration::Configuration,
    params: UpdateAttendanceTransactionsResourceParams,
) -> Result<
    crate::http::models::AttendanceTransactionWrap,
    Error<UpdateAttendanceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;
    let attendance_transaction = params.attendance_transaction;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/attendancetransactions/{id}",
        local_var_configuration.base_path,
        id = crate::http::apis::urlencode(id)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&attendance_transaction);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UpdateAttendanceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
