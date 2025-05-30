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

/// struct for passing parameters to the method [`cancel_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct CancelOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
}

/// struct for passing parameters to the method [`create_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateOrdersResourceParams {
    /// order to create
    pub order: Option<crate::http::models::OrderWrap>,
}

/// struct for passing parameters to the method [`createinvoice_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct CreateinvoiceOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
}

/// struct for passing parameters to the method [`email_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct EmailOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
}

/// struct for passing parameters to the method [`externalprint_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct ExternalprintOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
}

/// struct for passing parameters to the method [`get_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct GetOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
}

/// struct for passing parameters to the method [`list_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct ListOrdersResourceParams {
    /// possibility to filter orders
    pub filter: Option<String>,
}

/// struct for passing parameters to the method [`preview_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct PreviewOrdersResourceParams {
    /// identifies the offer
    pub document_number: String,
}

/// struct for passing parameters to the method [`print_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct PrintOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
}

/// struct for passing parameters to the method [`update_orders_resource`]
#[derive(Clone, Debug, Default)]
pub struct UpdateOrdersResourceParams {
    /// identifies the order
    pub document_number: String,
    /// order to update
    pub order: Option<crate::http::models::OrderWrap>,
}

/// struct for typed errors of method [`cancel_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CancelOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`create_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`createinvoice_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CreateinvoiceOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`email_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EmailOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`externalprint_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExternalprintOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`get_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`list_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`preview_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PreviewOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`print_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrintOrdersResourceError {
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`update_orders_resource`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateOrdersResourceError {
    UnknownValue(serde_json::Value),
}

pub async fn cancel_orders_resource(
    configuration: &configuration::Configuration,
    params: CancelOrdersResourceParams,
) -> Result<crate::http::models::OrderWrap, Error<CancelOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}/cancel",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CancelOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// An endpoint for creating an order.   Should you have EasyVat enabled, it is mandatory to provide an account in the request should you use a custom VAT rate.   This endpoint can produce errors, some of which may only be relevant for EasyVat. Refer to the table below.  <table>  <caption>Errors that can be raised by this endpoint.</caption>    <tr>     <th>Error Code</th>     <th>HTTP Code</th>     <th>Description</th>     <th>Solution</th>    </tr>    <tr>     <td>2004167</td>     <td>400</td>     <td>An account must be provided when using a custom VAT rate and EasyVat has been enabled.</td>     <td>Supply each row which has a custom VAT rate with an account.</td>    </tr>  </table>
pub async fn create_orders_resource(
    configuration: &configuration::Configuration,
    params: CreateOrdersResourceParams,
) -> Result<crate::http::models::OrderWrap, Error<CreateOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let order = params.order;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/orders/", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&order);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn createinvoice_orders_resource(
    configuration: &configuration::Configuration,
    params: CreateinvoiceOrdersResourceParams,
) -> Result<crate::http::models::InvoiceWrap, Error<CreateinvoiceOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}/createinvoice",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<CreateinvoiceOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// You can use the properties in the EmailInformation to customize the e-mail message on each order.
pub async fn email_orders_resource(
    configuration: &configuration::Configuration,
    params: EmailOrdersResourceParams,
) -> Result<crate::http::models::OrderWrap, Error<EmailOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}/email",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        let local_var_entity: Option<EmailOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Use this endpoint to set order as sent, without generating an order.
pub async fn externalprint_orders_resource(
    configuration: &configuration::Configuration,
    params: ExternalprintOrdersResourceParams,
) -> Result<crate::http::models::OrderWrap, Error<ExternalprintOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}/externalprint",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<ExternalprintOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn get_orders_resource(
    configuration: &configuration::Configuration,
    params: GetOrdersResourceParams,
) -> Result<crate::http::models::OrderWrap, Error<GetOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        let local_var_entity: Option<GetOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn list_orders_resource(
    configuration: &configuration::Configuration,
    params: ListOrdersResourceParams,
) -> Result<crate::http::models::OrderListItemList, Error<ListOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let filter = params.filter;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/3/orders/", local_var_configuration.base_path);
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
        let local_var_entity: Option<ListOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// The difference between this and the print-endpoint is that property Sent is not set to TRUE.
pub async fn preview_orders_resource(
    configuration: &configuration::Configuration,
    params: PreviewOrdersResourceParams,
) -> Result<String, Error<PreviewOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}/preview",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        let local_var_entity: Option<PreviewOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn print_orders_resource(
    configuration: &configuration::Configuration,
    params: PrintOrdersResourceParams,
) -> Result<String, Error<PrintOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}/print",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
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
        let local_var_entity: Option<PrintOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

/// Note that there are two approaches for updating the rows on an order.   If RowId is not specified on any row, the rows will be mapped and updated in the order in which they are set in the array. All rows that should remain on the order needs to be provided.   If RowId is specified on one or more rows the following goes: Corresponding row with that id will be updated. The rows without RowId will be interpreted as new rows. If a row should not be updated but remain on the order then specify only RowId like { \"RowId\": 123 }, otherwise it will be removed. Note that new RowIds are generated for all rows every time an order is updated.
pub async fn update_orders_resource(
    configuration: &configuration::Configuration,
    params: UpdateOrdersResourceParams,
) -> Result<crate::http::models::OrderWrap, Error<UpdateOrdersResourceError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let document_number = params.document_number;
    let order = params.order;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!(
        "{}/3/orders/{DocumentNumber}",
        local_var_configuration.base_path,
        DocumentNumber = crate::http::apis::urlencode(document_number)
    );
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::PUT, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    local_var_req_builder = local_var_req_builder.json(&order);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        tracing::trace!("Response: {}", local_var_content);
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<UpdateOrdersResourceError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
