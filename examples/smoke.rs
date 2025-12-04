use std::collections::BTreeMap;

use chrono::NaiveDate;
use fortnox::{
    http::models::{Customer, Invoice, InvoiceListItem},
    id::CustomerId,
    Client, CreateInvoice, InvoiceItem, OAuthClient, OAuthCredentials, UpdateCustomer,
};

use rust_decimal::Decimal;
use serde_derive::Serialize;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    run().await.unwrap()
}

// type Dump = BTreeMap<String, >

#[derive(Serialize)]
struct CustomerDump {
    pub customer: Customer,
    pub invoices: Vec<Invoice>,
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

    let client = Client::new(
        client,
        OAuthCredentials::load("./uhoh2.json") //"/Users/brendan/git/meela/meelasrv-static/fortnox-creds.json")
            .unwrap(),
    );

    let raw_customers = client.list_customers().await.unwrap();

    // eprintln!("{:#?}", &customers);
    let mut customers = vec![];

    'customer: for c in raw_customers {
        let id = c.customer_number.unwrap();
        println!("Customer: {}", &id);

        let c = loop {
            match client.customer(&id).await {
                Ok(v) => break v,
                Err(e) => match e {
                    fortnox::Error::ResponseError(e) => {
                        if e.status == 429 {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                        panic!("{:#?}", e);
                    }
                    other => {
                        eprintln!("{:#?}", other);
                        continue 'customer;
                    }
                },
            }
        };

        println!("List invoices");
        let x = loop {
            match client.list_invoices(&id, None).await {
                Ok(v) => break v,
                Err(e) => match e {
                    fortnox::Error::ResponseError(e) => {
                        if e.status == 429 {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                        panic!("{:#?}", e);
                    }
                    other => {
                        eprintln!("{:#?}", other);
                        continue 'customer;
                    }
                },
            }
        };

        let mut invoices = vec![];

        for inv in x {
            let iid = inv.document_number.unwrap();
            println!("Invoice: {}", &iid);
            let i = loop {
                match client.invoice(&iid).await {
                    Ok(v) => break v,
                    Err(e) => match e {
                        fortnox::Error::ResponseError(e) => {
                            if e.status == 429 {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                continue;
                            }
                            panic!("{:#?}", e);
                        }
                        other => {
                            eprintln!("{:#?}", other);
                            continue 'customer;
                        }
                    },
                }
            };

            invoices.push(i);
            // eprintln!("{} {}: {:?}", &id, &iid, &i.invoice_rows.unwrap_or_default());
        }

        customers.push(CustomerDump {
            customer: c,
            invoices,
        });
    }

    let s = serde_json::to_string_pretty(&customers).unwrap();
    std::fs::write("./fortnox-dump.json", s).unwrap();

    // let customer_id = CustomerId::<'T'>::from_uuid(
    //     Uuid::parse_str("B0EE201C-2A4F-4C9E-BF3B-717FEE561615").unwrap(),
    // );

    // let details = UpdateCustomer {
    //     org_nr: "1234567890".to_string().into(),
    //     name: "Test test".to_string().into(),
    //     address1: "boop 1234".to_string().into(),
    //     address2: fortnox::Update::Null,
    //     city: "Town".to_string().into(),
    //     post_code: "AE1234".to_string().into(),
    //     country_code: "SE".to_string().into(),
    //     active: true.into(),
    //     email: "brendan@meelahealth.com".to_string().into(),
    //     email_invoice: fortnox::Update::Null,
    //     external_reference: fortnox::Update::Null,
    // };

    // let result = client
    //     .create_or_update_customer(customer_id, details.clone())
    //     .await?;

    // let details = CreateInvoice {
    //     customer_id,
    //     due_date: None,
    //     invoice_date: Some(NaiveDate::from_ymd_opt(2023, 06, 01).unwrap()),
    //     payment_terms: Some("30".into()),
    //     items: vec![InvoiceItem {
    //         account_number: 3001,
    //         count: 31,
    //         description: "Potato".into(),
    //         price: Decimal::new(10025, 2),
    //         vat: Default::default(),
    //     }],
    // };

    // let result = client.create_invoice(details.clone()).await?;
    // client
    //     .book_invoice(&result.document_number.as_ref().unwrap())
    //     .await?;

    // client
    //     .send_invoice(&result.document_number.as_ref().unwrap())
    //     .await?;

    // let result = client.create_invoice(details.clone()).await?;
    // // client
    // //     .book_invoice(&result.document_number.as_ref().unwrap())
    // //     .await?;

    // let result = client.create_invoice(details.clone()).await?;
    // client
    //     .book_invoice(&result.document_number.as_ref().unwrap())
    //     .await?;

    // let update = UpdateCustomer {
    //     org_nr: "1231231231".to_string().into(),
    //     name: "New Name AB".to_string().into(),
    //     email_invoice: fortnox::Update::Null,
    //     ..Default::default()
    // };

    // client.update_customer(customer_id, update).await?;

    // let invoice_pdf_data = client
    //     .download_invoice_pdf(&result.document_number.as_ref().unwrap())
    //     .await?;
    // let result = client
    //     .refund_invoice(&result.document_number.unwrap())
    //     .await?;
    // let credit_id = result.credit_invoice_reference.unwrap();
    // let credit_pdf_data = client.download_invoice_pdf(&credit_id).await?;

    // let results = client.list_invoices(customer_id).await?;
    // println!("{:#?}", results);

    Ok(())
}
