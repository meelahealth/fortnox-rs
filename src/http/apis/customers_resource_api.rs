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

/// struct for passing parameters to the method [`create_customers_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateCustomersResourceParams {
    /// customer to create
    pub customer: Option<crate::http::models::CustomerWrap>,
}

/// struct for passing parameters to the method [`get_customers_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetCustomersResourceParams {
    /// identifies the customer
    pub customer_number: String,
}

/// struct for passing parameters to the method [`list_customers_resource`]
#[derive(Clone, Debug, Default)]
pub struct ListCustomersResourceParams {
    /// possibility to filter customers
    pub filter: Option<String>,
}

/// struct for passing parameters to the method [`remove_customers_resource`]
#[derive(Clone, Debug, Default)]
pub struct RemoveCustomersResourceParams {
    /// identifies the customer
    pub customer_number: String,
}

/// struct for passing parameters to the method [`update_customers_resource`]
#[derive(Clone, Debug, Default)]
pub struct UpdateCustomersResourceParams {
    /// identifies the customer
    pub customer_number: String,
    /// customer to update
    pub customer: crate::http::models::CustomerWrap,
}

/// struct for typed errors of method [`create_customers_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateCustomersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_customers_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetCustomersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`list_customers_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListCustomersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`remove_customers_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RemoveCustomersResourceError {
    DefaultResponse(),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`update_customers_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateCustomersResourceError {
    UnknownValue(serde_json::Value),
}

/// The created customer will be returned if everything succeeded, if there was any problems an error will be returned.
pub async fn create_customers_resource(
    configuration: &configuration::Configuration,
    params: CreateCustomersResourceParams,
) -> Result<crate::http::models::CustomerWrap, Error<CreateCustomersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let customer = params.customer;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/customers/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&customer);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateCustomersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// You need to supply the unique customer number that was returned when the customer was created or retrieved from the list of customers.
pub async fn get_customers_resource(
    configuration: &configuration::Configuration,
    params: GetCustomersResourceParams,
) -> Result<crate::http::models::CustomerWrap, Error<GetCustomersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let customer_number = params.customer_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/customers/{CustomerNumber}",
        local_var_configuration.base_path,
        CustomerNumber = crate::http::apis::urlencode(customer_number)
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
        let local_var_entity: Option<GetCustomersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The customers are returned sorted by customer number with the lowest number appearing first.
pub async fn list_customers_resource(
    configuration: &configuration::Configuration,
    params: ListCustomersResourceParams,
) -> Result<crate::http::models::CustomerListItemList, Error<ListCustomersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let filter = params.filter;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/customers/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = filter {
        local_var_req_builder =
            local_var_req_builder.query(&[("filter", &local_var_str.to_string())]);
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
        let local_var_entity: Option<ListCustomersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Deletes the customer permanently. If everything succeeded the response will be of the type 204 \\u2013 No content and the response body will be empty. If there was any problems an error will be returned.  You need to supply the unique customer number of the customer that you want to delete.
pub async fn remove_customers_resource(
    configuration: &configuration::Configuration,
    params: RemoveCustomersResourceParams,
) -> Result<(), Error<RemoveCustomersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let customer_number = params.customer_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/customers/{CustomerNumber}",
        local_var_configuration.base_path,
        CustomerNumber = crate::http::apis::urlencode(customer_number)
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
        Ok(())
    } else {
        let local_var_entity: Option<RemoveCustomersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// <p>The updated customer will be returned if everything succeeded, if there was any problems an error will be returned.</p>  <p>You need to supply the unique customer number of the customer that you want to update.</p>  <p>Only the properties provided in the request body will be updated, properties not provided will left unchanged.</p>
pub async fn update_customers_resource(
    configuration: &configuration::Configuration,
    params: UpdateCustomersResourceParams,
) -> Result<crate::http::models::CustomerWrap, Error<UpdateCustomersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let customer_number = params.customer_number;
    let customer = params.customer;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/customers/{CustomerNumber}",
        local_var_configuration.base_path,
        CustomerNumber = crate::http::apis::urlencode(customer_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&customer);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UpdateCustomersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
