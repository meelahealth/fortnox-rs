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

/// struct for passing parameters to the method [`create_absence_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateAbsenceTransactionsResourceParams {
    /// to create
    pub absence_transactions_payload: Option<crate::http::models::AbsenceTransactionPayloadWrap>,
}

/// struct for passing parameters to the method [`get_absence_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetAbsenceTransactionsResourceParams {
    /// identifies the transaction
    pub id: String,
}

/// struct for passing parameters to the method [`get_absence_transactions_resource1`]
#[derive(Clone, Debug, Default)]
pub struct GetAbsenceTransactionsResource1Params {
    /// identifies the employee
    pub employee_id: String,
    /// of the absence transaction
    pub date: String,
    /// status code of the absence transaction
    pub code: String,
}

/// struct for passing parameters to the method [`list_absence_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct ListAbsenceTransactionsResourceParams {
    /// filter by employee id
    pub employeeid: Option<String>,
    /// filter by date
    pub date: Option<String>,
}

/// struct for passing parameters to the method [`remove`]
#[derive(Clone, Debug, Default)]
pub struct RemoveParams {
    /// identifies the transaction
    pub id: String,
}

/// struct for passing parameters to the method [`update_absence_transactions_resource`]
#[derive(Clone, Debug, Default)]
pub struct UpdateAbsenceTransactionsResourceParams {
    /// identifies the transaction
    pub id: String,
    /// to update
    pub absence_transactions_payload: Option<crate::http::models::AbsenceTransactionPayloadWrap>,
}

/// struct for typed errors of method [`create_absence_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateAbsenceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_absence_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAbsenceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_absence_transactions_resource1`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAbsenceTransactionsResource1Error {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`list_absence_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListAbsenceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`remove`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RemoveError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`update_absence_transactions_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateAbsenceTransactionsResourceError {
    UnknownValue(serde_json::Value),
}

pub async fn create_absence_transactions_resource(
    configuration: &configuration::Configuration,
    params: CreateAbsenceTransactionsResourceParams,
) -> Result<
    crate::http::models::AbsenceTransactionSingleItemWrap,
    Error<CreateAbsenceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let absence_transactions_payload = params.absence_transactions_payload;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/absencetransactions",
        local_var_configuration.base_path
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&absence_transactions_payload);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateAbsenceTransactionsResourceError> =
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
pub async fn get_absence_transactions_resource(
    configuration: &configuration::Configuration,
    params: GetAbsenceTransactionsResourceParams,
) -> Result<
    crate::http::models::AbsenceTransactionSingleItemWrap,
    Error<GetAbsenceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/absencetransactions/{id}",
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
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<GetAbsenceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Retrieves a list of absence transactions for an employee on a specific date and cause code.
pub async fn get_absence_transactions_resource1(
    configuration: &configuration::Configuration,
    params: GetAbsenceTransactionsResource1Params,
) -> Result<
    crate::http::models::AbsenceTransactionListItemWrap,
    Error<GetAbsenceTransactionsResource1Error>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let employee_id = params.employee_id;
    let date = params.date;
    let code = params.code;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/absencetransactions/{EmployeeId}/{Date}/{Code}",
        local_var_configuration.base_path,
        EmployeeId = crate::http::apis::urlencode(employee_id),
        Date = date,
        Code = crate::http::apis::urlencode(code)
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
        let local_var_entity: Option<GetAbsenceTransactionsResource1Error> =
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
pub async fn list_absence_transactions_resource(
    configuration: &configuration::Configuration,
    params: ListAbsenceTransactionsResourceParams,
) -> Result<
    crate::http::models::AbsenceTransactionListItemWrap,
    Error<ListAbsenceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let employeeid = params.employeeid;
    let date = params.date;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/absencetransactions",
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
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ListAbsenceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn remove(
    configuration: &configuration::Configuration,
    params: RemoveParams,
) -> Result<crate::http::models::AbsenceTransactionSingleItemWrap, Error<RemoveError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/absencetransactions/{id}",
        local_var_configuration.base_path,
        id = crate::http::apis::urlencode(id)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::DELETE, local_var_uri_str.as_str());

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
        let local_var_entity: Option<RemoveError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn update_absence_transactions_resource(
    configuration: &configuration::Configuration,
    params: UpdateAbsenceTransactionsResourceParams,
) -> Result<
    crate::http::models::AbsenceTransactionSingleItemWrap,
    Error<UpdateAbsenceTransactionsResourceError>,
> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let id = params.id;
    let absence_transactions_payload = params.absence_transactions_payload;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/absencetransactions/{id}",
        local_var_configuration.base_path,
        id = crate::http::apis::urlencode(id)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&absence_transactions_payload);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UpdateAbsenceTransactionsResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
