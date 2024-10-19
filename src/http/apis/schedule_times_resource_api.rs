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

/// struct for passing parameters to the method [`get_schedule_times_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetScheduleTimesResourceParams {
    /// identifies the employee
    pub employee_id: String,
    /// identifies the date
    pub date: String,
}

/// struct for passing parameters to the method [`reset`]
#[derive(Clone, Debug, Default)]
pub struct ResetParams {
    /// identifies the employee
    pub employee_id: String,
    /// identifies the date
    pub date: String,
}

/// struct for passing parameters to the method [`update_schedule_times_resource`]
#[derive(Clone, Debug, Default)]
pub struct UpdateScheduleTimesResourceParams {
    /// identifies the employee
    pub employee_id: String,
    /// identifies the date
    pub date: String,
    /// to update
    pub schedule_time: Option<crate::http::models::ScheduleTimeWrap>,
}

/// struct for typed errors of method [`get_schedule_times_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetScheduleTimesResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`reset`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResetError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`update_schedule_times_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateScheduleTimesResourceError {
    UnknownValue(serde_json::Value),
}

pub async fn get_schedule_times_resource(
    configuration: &configuration::Configuration,
    params: GetScheduleTimesResourceParams,
) -> Result<crate::http::models::ScheduleTimeWrap, Error<GetScheduleTimesResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let employee_id = params.employee_id;
    let date = params.date;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/scheduletimes/{EmployeeId}/{Date}",
        local_var_configuration.base_path,
        EmployeeId = crate::http::apis::urlencode(employee_id),
        Date = date
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
        let local_var_entity: Option<GetScheduleTimesResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn reset(
    configuration: &configuration::Configuration,
    params: ResetParams,
) -> Result<crate::http::models::ScheduleTimeWrap, Error<ResetError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let employee_id = params.employee_id;
    let date = params.date;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/scheduletimes/{EmployeeId}/{Date}/resetday",
        local_var_configuration.base_path,
        EmployeeId = crate::http::apis::urlencode(employee_id),
        Date = date
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
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ResetError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn update_schedule_times_resource(
    configuration: &configuration::Configuration,
    params: UpdateScheduleTimesResourceParams,
) -> Result<crate::http::models::ScheduleTimeWrap, Error<UpdateScheduleTimesResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let employee_id = params.employee_id;
    let date = params.date;
    let schedule_time = params.schedule_time;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/scheduletimes/{EmployeeId}/{Date}",
        local_var_configuration.base_path,
        EmployeeId = crate::http::apis::urlencode(employee_id),
        Date = date
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&schedule_time);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::debug!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UpdateScheduleTimesResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
