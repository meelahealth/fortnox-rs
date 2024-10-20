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

/// struct for passing parameters to the method [`list`]
#[derive(Clone, Debug, Default)]
pub struct ListParams {
    /// The start date of the search span, the max of which should be 1 year to the end date (\"toDate\").  Example: 2022-11-01
    pub from_date: Option<String>,
    /// The end date of the search span, the max of which should be 1 year back to the start date (\"fromDate\").  Example: 2022-11-30
    pub to_date: Option<String>,
    /// An array of customer IDs which are being used in database and in one-to-one relation with customer numbers.  Example: 100,101,102
    pub customer_ids: Option<Vec<String>>,
    /// An array of project IDs.  Example: p1,p2,p3
    pub project_ids: Option<Vec<String>>,
    /// If the article registration without project is included, or not.
    pub include_registrations_without_project: Option<bool>,
    /// An array of article IDs.  Example: s1,s2,s3
    pub item_ids: Option<Vec<String>>,
    /// An array of cost center IDs.  Example: cc1,cc2,cc3
    pub cost_center_ids: Option<Vec<String>>,
    /// An array of user ids who own the article registrations.  Example: 1,2,3
    pub owner_ids: Option<Vec<String>>,
    /// If a document is created with the article registration, or not.
    pub invoiced: Option<bool>,
    /// If the article registration is locked on an invoice basis, or not.
    pub in_invoice_basis: Option<bool>,
    /// If the article registration is internal, which is registered on an internal customer, or not.
    pub internal_articles: Option<bool>,
    /// If the article registration has been moved to non-invoiceable, or not.
    pub non_invoiceable: Option<bool>,
    /// If the price of the non-invoiceable article registration is included, or not.
    pub include_non_invoiceable_price: Option<bool>,
}

/// struct for typed errors of method [`list`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListError {
    UnknownValue(serde_json::Value),
}

/// <p>  <b>Response property descriptions:</b><br/>  &nbsp;&nbsp;&nbsp;&nbsp;    <b><i>id</i></b> - The unique id of a basic common combination of article registrations. (The basic common combination means \"user/purchase date/customer/project/cost center\", which leads to a dialog with several article registrations.)<br/>  &nbsp;&nbsp;&nbsp;&nbsp;    <b><i>purchaseDate</i></b> - The date on which the article is purchased or registered for charging.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;    <b><i>ownerId</i></b> - The user ID who creates the basic common combination.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;    <b><i>version</i></b> - The version of the basic common combination (article dialog) being updated, which is used for handling the concurrency issue.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;    <b><i>registrationType</i></b> - It is always \"ARTICLE\" for article list endpoint.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;    <b>Sub-Class - ArticleRegistration:</b><br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>id</i></b> - The unique id of an article registration.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>registrationId</i></b> - The id of the basic common combination.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>orderIndex</i></b> - the order index for the article registration in regard of the common combination.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>ownerId</i></b> - The user ID who owns the article registration.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>totalQuantity</i></b> - The quantity of the article.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>unitPrice</i></b> - The unit price connected to the article registration, which might be locked on an invoice/order basis or for non-invoiceable.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>unitCost</i></b> - The unit cost connected to the article registration, which might be locked on an invoice/order basis.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>invoiceBasisId</i></b> - The ID of invoice/order basis which is used for creating an invoice/order.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>nonInvoiceable</i></b> - If the article registration would be ignored for charging or not.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>note</i></b> - The note on the article registration.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>documentId</i></b> - The document ID which includes the article registration and is created in Invoicing application.<br/>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;        <b><i>documentType</i></b> - The document type which could be \"invoice\" or \"order\".  </p>
pub async fn list(
    configuration: &configuration::Configuration,
    params: ListParams,
) -> Result<Vec<crate::http::models::BaseArticleRegistration>, Error<ListError>> {
    let local_var_configuration = configuration;

    // unbox the parameters
    let from_date = params.from_date;
    let to_date = params.to_date;
    let customer_ids = params.customer_ids;
    let project_ids = params.project_ids;
    let include_registrations_without_project = params.include_registrations_without_project;
    let item_ids = params.item_ids;
    let cost_center_ids = params.cost_center_ids;
    let owner_ids = params.owner_ids;
    let invoiced = params.invoiced;
    let in_invoice_basis = params.in_invoice_basis;
    let internal_articles = params.internal_articles;
    let non_invoiceable = params.non_invoiceable;
    let include_non_invoiceable_price = params.include_non_invoiceable_price;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/api/time/articles-v1", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::GET, local_var_uri_str.as_str());

    if let Some(ref local_var_str) = from_date {
        local_var_req_builder =
            local_var_req_builder.query(&[("fromDate", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = to_date {
        local_var_req_builder =
            local_var_req_builder.query(&[("toDate", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = customer_ids {
        local_var_req_builder = match "multi" {
            "multi" => local_var_req_builder.query(
                &local_var_str
                    .iter()
                    .map(|p| ("customerIds".to_owned(), p.to_string()))
                    .collect::<Vec<(std::string::String, std::string::String)>>(),
            ),
            _ => local_var_req_builder.query(&[(
                "customerIds",
                &local_var_str
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            )]),
        };
    }
    if let Some(ref local_var_str) = project_ids {
        local_var_req_builder = match "multi" {
            "multi" => local_var_req_builder.query(
                &local_var_str
                    .iter()
                    .map(|p| ("projectIds".to_owned(), p.to_string()))
                    .collect::<Vec<(std::string::String, std::string::String)>>(),
            ),
            _ => local_var_req_builder.query(&[(
                "projectIds",
                &local_var_str
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            )]),
        };
    }
    if let Some(ref local_var_str) = include_registrations_without_project {
        local_var_req_builder = local_var_req_builder.query(&[(
            "includeRegistrationsWithoutProject",
            &local_var_str.to_string(),
        )]);
    }
    if let Some(ref local_var_str) = item_ids {
        local_var_req_builder = match "multi" {
            "multi" => local_var_req_builder.query(
                &local_var_str
                    .iter()
                    .map(|p| ("itemIds".to_owned(), p.to_string()))
                    .collect::<Vec<(std::string::String, std::string::String)>>(),
            ),
            _ => local_var_req_builder.query(&[(
                "itemIds",
                &local_var_str
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            )]),
        };
    }
    if let Some(ref local_var_str) = cost_center_ids {
        local_var_req_builder = match "multi" {
            "multi" => local_var_req_builder.query(
                &local_var_str
                    .iter()
                    .map(|p| ("costCenterIds".to_owned(), p.to_string()))
                    .collect::<Vec<(std::string::String, std::string::String)>>(),
            ),
            _ => local_var_req_builder.query(&[(
                "costCenterIds",
                &local_var_str
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            )]),
        };
    }
    if let Some(ref local_var_str) = owner_ids {
        local_var_req_builder = match "multi" {
            "multi" => local_var_req_builder.query(
                &local_var_str
                    .iter()
                    .map(|p| ("ownerIds".to_owned(), p.to_string()))
                    .collect::<Vec<(std::string::String, std::string::String)>>(),
            ),
            _ => local_var_req_builder.query(&[(
                "ownerIds",
                &local_var_str
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            )]),
        };
    }
    if let Some(ref local_var_str) = invoiced {
        local_var_req_builder =
            local_var_req_builder.query(&[("invoiced", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = in_invoice_basis {
        local_var_req_builder =
            local_var_req_builder.query(&[("inInvoiceBasis", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = internal_articles {
        local_var_req_builder =
            local_var_req_builder.query(&[("internalArticles", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = non_invoiceable {
        local_var_req_builder =
            local_var_req_builder.query(&[("nonInvoiceable", &local_var_str.to_string())]);
    }
    if let Some(ref local_var_str) = include_non_invoiceable_price {
        local_var_req_builder = local_var_req_builder
            .query(&[("includeNonInvoiceablePrice", &local_var_str.to_string())]);
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
        let local_var_entity: Option<ListError> = serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
