use chrono::NaiveDate;
use fortnox::{
    id::CustomerId, Client, CreateCustomer, CreateInvoice, InvoiceItem, OAuthClient,
    OAuthCredentials, UpdateCustomer,
};

use rust_decimal::Decimal;

#[tokio::main]
async fn main() {
    run().await.unwrap()
}

async fn run() -> anyhow::Result<()> {
    use reqwest::header;

    // auth("c1672dc4-c604-4cef-b283-29a3803c0dc9").await.unwrap();
    // panic!();

    // let bearer_token = "37c03f63-470d-4adf-ac7f-a6b56e8c5b93";

    let client = OAuthClient::new(
        "7rbJ0CjpBqdj",
        "e93nZK3ej7",
        url::Url::parse("http://localhost")?,
    );
    // let (url, blah) = client.authenticate(Scope::all());
    // println!("{url} {blah:?}");
    // panic!();

    // let res = client.exchange_code("59fefde9-0ed5-464b-9e03-ccefba9580dc").await?;

    // let access_token = res.access_token().clone();
    // let refresh_token = res.refresh_token().cloned();
    // let expires_at = Utc::now() + chrono::Duration::seconds(res.expires_in().unwrap().as_secs() as _);

    // let creds = OAuthCredentials {
    //     persistence_path: "./uhoh.json".into(),
    //     access_token: access_token,
    //     refresh_token: refresh_token,
    //     expires_at: Some(expires_at),
    // };

    // creds.save().unwrap();

    let client = Client::new(client, OAuthCredentials::load("./uhoh.json").unwrap());

    let customer_id = CustomerId::<'T'>::random();

    let details = CreateCustomer {
        id: customer_id,
        org_nr: "1234567890".to_string(),
        name: "Test test".into(),
        address1: "boop 123".into(),
        address2: None,
        city: "Town".into(),
        post_code: "AE1234".into(),
        country_code: "SE".into(),
        active: true,
        email: "boop@invalid.example".into(),
        email_invoice: None,
        external_reference: None,
    };

    let result = client.create_customer(details.clone()).await?;

    let details = CreateInvoice {
        customer_id: details.id,
        due_date: None,
        invoice_date: Some(NaiveDate::from_ymd_opt(2023, 06, 01).unwrap()),
        payment_terms: Some("30".into()),
        items: vec![InvoiceItem {
            account_number: 3001,
            count: 31,
            description: "Potato".into(),
            price: Decimal::new(10025, 2),
            vat: Default::default(),
        }],
    };

    let result = client.create_invoice(details.clone()).await?;
    client
        .book_invoice(&result.document_number.as_ref().unwrap())
        .await?;

    let result = client.create_invoice(details.clone()).await?;
    // client
    //     .book_invoice(&result.document_number.as_ref().unwrap())
    //     .await?;

    let result = client.create_invoice(details.clone()).await?;
    client
        .book_invoice(&result.document_number.as_ref().unwrap())
        .await?;

    let update = UpdateCustomer {
        org_nr: "1231231231".to_string().into(),
        name: "New Name AB".to_string().into(),
        email_invoice: fortnox::Update::Null,
        ..Default::default()
    };

    client.update_customer(customer_id, update).await?;

    let invoice_pdf_data = client
        .download_invoice_pdf(&result.document_number.as_ref().unwrap())
        .await?;
    let result = client
        .refund_invoice(&result.document_number.unwrap())
        .await?;
    let credit_id = result.credit_invoice_reference.unwrap();
    let credit_pdf_data = client.download_invoice_pdf(&credit_id).await?;

    let results = client.list_invoices(customer_id).await?;
    println!("{:#?}", results);

    Ok(())
}
