use aws_config::Region;
use aws_credential_types::provider::ProvideCredentials;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignatureLocation, SigningParams, SigningSettings};
use aws_sigv4::sign::v4::SigningParams as V4SigningParams;
use http::{Method, Request};
use serde::Serialize;
use std::time::SystemTime;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

async fn aws_subject_token(
    regional_cred_verification_url: &str,
    credentials: Credentials,
    region: Region,
    sign_at: SystemTime,
    audience: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let identity = credentials.into();

    let mut signing_settings = SigningSettings::default();
    signing_settings.signature_location = SignatureLocation::Headers;
    let v4_signing_params = V4SigningParams::builder()
        .name("sts")
        .identity(&identity)
        .region(region.as_ref())
        .time(sign_at)
        .settings(signing_settings)
        .build()?;
    let params = SigningParams::V4(v4_signing_params);

    let regional_cred_verification_url =
        regional_cred_verification_url.replace("{region}", region.as_ref());
    let subject_token_url = regional_cred_verification_url;
    let url = url::Url::parse(&subject_token_url).unwrap();
    let method = Method::POST;
    let mut headers = vec![("x-goog-cloud-target-resource", audience)];
    if let Some(host) = url.host_str() {
        headers.push(("Host", host))
    }
    let mut req = Request::builder().uri(url.to_string()).method(&method);
    for header in &headers {
        req = req.header(header.0, header.1);
    }
    let mut request = req.body(()).unwrap();

    let signable_request = aws_sigv4::http_request::SignableRequest::new(
        method.as_str(),
        &subject_token_url,
        headers.into_iter(),
        SignableBody::empty(),
    )?;
    let (instruction, _) = aws_sigv4::http_request::sign(signable_request, &params)
        .unwrap()
        .into_parts();
    instruction.apply_to_request_http1x(&mut request);
    let payload = AWSRequest {
        url: subject_token_url.to_string(),
        method: method.to_string(),
        headers: request
            .headers()
            .into_iter()
            .flat_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| AWSRequestHeader::new(k.to_string(), v.to_string()))
            })
            .collect(),
    };
    let payload = serde_json::to_string(&payload).expect("out");
    let sts_token = utf8_percent_encode(&payload, NON_ALPHANUMERIC).to_string();

    Ok(sts_token)
}

#[derive(Debug, Serialize)]
struct AWSRequest {
    url: String,
    method: String,
    headers: Vec<AWSRequestHeader>,
}

#[derive(Debug, Serialize, Clone)]
struct AWSRequestHeader {
    key: String,
    value: String,
}

impl AWSRequestHeader {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

async fn get_aws_props() -> Result<(Credentials, Region), Box<dyn std::error::Error>> {
    let credentials_provider =
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .build()
            .await;
    let imds_region_provider =
        aws_config::default_provider::region::DefaultRegionChain::builder().build();
    let config = aws_config::load_from_env().await;
    let region = match config.region() {
        Some(region) => Some(region.to_owned()),
        None => imds_region_provider.region().await,
    }
    .expect("reagion unknown");
    let provide_credentials = { credentials_provider.provide_credentials().await };
    let credentials: Credentials = provide_credentials?.into();
    Ok((credentials, region))
}

#[cfg(test)]
mod tests {

    use aws_config::Region;
    use aws_credential_types::Credentials;
    use chrono::NaiveDateTime;

    use crate::aws_subject_token;
    #[tokio::test]
    async fn g() {
        let credentials = Credentials::new(
            "AccessKeyId",
            "SecretAccessKey",
            Some("SecurityToken".to_string()),
            None,
            "test",
        );
        //1983 Apr 13 12:09:14.274 +0000
        // "%Y %b %d %H:%M:%S%.3f %z"
        let sign_at = NaiveDateTime::parse_from_str("2022-12-31 00:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
            .into();
        let region = Region::from_static("ap-northeast-1b");
        let audience = "//iam.googleapis.com/projects/myprojectnumber/locations/global/workloadIdentityPools/aws-test/providers/aws-test";
        let regional_cred_verification_url =
            "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";
        let result = aws_subject_token(
            regional_cred_verification_url,
            credentials,
            region.clone(),
            sign_at,
            audience,
        )
        .await;
        assert_eq!(result.unwrap(),"%7B%22url%22%3A%22https%3A%2F%2Fsts%2Eap%2Dnortheast%2D1b%2Eamazonaws%2Ecom%3FAction%3DGetCallerIdentity%26Version%3D2011%2D06%2D15%22%2C%22method%22%3A%22POST%22%2C%22headers%22%3A%5B%7B%22key%22%3A%22x%2Dgoog%2Dcloud%2Dtarget%2Dresource%22%2C%22value%22%3A%22%2F%2Fiam%2Egoogleapis%2Ecom%2Fprojects%2Fmyprojectnumber%2Flocations%2Fglobal%2FworkloadIdentityPools%2Faws%2Dtest%2Fproviders%2Faws%2Dtest%22%7D%2C%7B%22key%22%3A%22host%22%2C%22value%22%3A%22sts%2Eap%2Dnortheast%2D1b%2Eamazonaws%2Ecom%22%7D%2C%7B%22key%22%3A%22x%2Damz%2Ddate%22%2C%22value%22%3A%2220221231T000000Z%22%7D%2C%7B%22key%22%3A%22authorization%22%2C%22value%22%3A%22AWS4%2DHMAC%2DSHA256%20Credential%3DAccessKeyId%2F20221231%2Fap%2Dnortheast%2D1b%2Fsts%2Faws4%5Frequest%2C%20SignedHeaders%3Dhost%3Bx%2Damz%2Ddate%3Bx%2Damz%2Dsecurity%2Dtoken%3Bx%2Dgoog%2Dcloud%2Dtarget%2Dresource%2C%20Signature%3D168a40df8b7c11fb0588a13cada1443e31e4736de702232f9a2177b26edda21c%22%7D%2C%7B%22key%22%3A%22x%2Damz%2Dsecurity%2Dtoken%22%2C%22value%22%3A%22SecurityToken%22%7D%5D%7D");
    }
    use crate::get_aws_props;
    #[tokio::test]
    async fn h() {
        let (credentials, region) = get_aws_props().await.unwrap();
        println!("{:?},{:?}", credentials, region);
        let sign_at = NaiveDateTime::parse_from_str("2022-12-31 00:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
            .into();
        let audience = "//iam.googleapis.com/projects/myprojectnumber/locations/global/workloadIdentityPools/aws-test/providers/aws-test";
        let regional_cred_verification_url =
            "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";
        let result = aws_subject_token(
            regional_cred_verification_url,
            credentials,
            region.clone(),
            sign_at,
            audience,
        )
        .await;
        assert_eq!(result.unwrap(),"%7B%22url%22%3A%22https%3A%2F%2Fsts%2Eap%2Dnortheast%2D1b%2Eamazonaws%2Ecom%3FAction%3DGetCallerIdentity%26Version%3D2011%2D06%2D15%22%2C%22method%22%3A%22POST%22%2C%22headers%22%3A%5B%7B%22key%22%3A%22x%2Dgoog%2Dcloud%2Dtarget%2Dresource%22%2C%22value%22%3A%22%2F%2Fiam%2Egoogleapis%2Ecom%2Fprojects%2Fmyprojectnumber%2Flocations%2Fglobal%2FworkloadIdentityPools%2Faws%2Dtest%2Fproviders%2Faws%2Dtest%22%7D%2C%7B%22key%22%3A%22host%22%2C%22value%22%3A%22sts%2Eap%2Dnortheast%2D1b%2Eamazonaws%2Ecom%22%7D%2C%7B%22key%22%3A%22x%2Damz%2Ddate%22%2C%22value%22%3A%2220221231T000000Z%22%7D%2C%7B%22key%22%3A%22authorization%22%2C%22value%22%3A%22AWS4%2DHMAC%2DSHA256%20Credential%3DAccessKeyId%2F20221231%2Fap%2Dnortheast%2D1b%2Fsts%2Faws4%5Frequest%2C%20SignedHeaders%3Dhost%3Bx%2Damz%2Ddate%3Bx%2Damz%2Dsecurity%2Dtoken%3Bx%2Dgoog%2Dcloud%2Dtarget%2Dresource%2C%20Signature%3D168a40df8b7c11fb0588a13cada1443e31e4736de702232f9a2177b26edda21c%22%7D%2C%7B%22key%22%3A%22x%2Damz%2Dsecurity%2Dtoken%22%2C%22value%22%3A%22SecurityToken%22%7D%5D%7D");
    }
}
