use anyhow::{bail, Context};
use nv_attestation_sdk::{
    EvidencePolicy, GpuEvidenceSource, GpuLocalVerifier, HttpOptions, Nonce, NvatSdk, OcspClient,
    RimStore,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{stdin, stdout, Write};

#[derive(Debug, Deserialize)]
struct Request {
    mode: Option<String>,
    nonce_hex: String,
    #[serde(default)]
    evidence_json: Option<Value>,
}

#[derive(Debug, Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_format: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_json: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims_json: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detached_eat_json: Option<Value>,
}

fn main() -> anyhow::Result<()> {
    let _sdk = NvatSdk::init_default().context("failed to initialize NVIDIA attestation SDK")?;

    let req: Request =
        serde_json::from_reader(stdin().lock()).context("failed to decode helper request")?;
    let nonce = Nonce::from_hex(&req.nonce_hex).context("failed to parse nonce")?;

    let resp = match req.mode.as_deref().unwrap_or("collect") {
        "collect" => collect_evidence(&nonce)?,
        "verify" => verify_evidence(&nonce, req.evidence_json)?,
        other => bail!("unsupported helper mode: {other}"),
    };

    let mut out = stdout().lock();
    serde_json::to_writer(&mut out, &resp).context("failed to write helper response")?;
    let _ = out.write_all(b"\n");

    Ok(())
}

fn collect_evidence(nonce: &Nonce) -> anyhow::Result<Response> {
    let evidence_source =
        GpuEvidenceSource::from_nvml().context("failed to create NVML evidence source")?;
    let evidence = evidence_source
        .collect(nonce)
        .context("failed to collect evidence")?;
    let evidence_json = evidence
        .to_json()
        .context("failed to serialize GPU evidence to JSON")?;
    let evidence_json: Value =
        serde_json::from_str(&evidence_json).context("failed to parse serialized evidence JSON")?;

    Ok(Response {
        vendor: Some("nvidia"),
        evidence_format: Some("nvat-json"),
        evidence_json: Some(evidence_json),
        claims_json: None,
        detached_eat_json: None,
    })
}

fn verify_evidence(nonce: &Nonce, evidence_json: Option<Value>) -> anyhow::Result<Response> {
    let evidence_json = evidence_json.context("verify mode requires evidence_json")?;
    let evidence_json = serde_json::to_string(&evidence_json)
        .context("failed to serialize evidence_json request field")?;

    let evidence_source = GpuEvidenceSource::from_json_string(&evidence_json)
        .context("failed to create JSON evidence source")?;
    let evidence = evidence_source
        .collect(nonce)
        .context("failed to load GPU evidence from JSON")?;

    if evidence.is_empty() {
        bail!("GPU evidence did not contain any devices");
    }

    let http_opts = HttpOptions::builder()
        .max_retry_count(5)
        .connection_timeout_ms(10000)
        .request_timeout_ms(30000)
        .build()
        .context("failed to create HTTP options")?;
    let rim_store = RimStore::create_remote(None, None, Some(&http_opts))
        .context("failed to create RIM store")?;
    let ocsp_client = OcspClient::create_default(None, None, Some(&http_opts))
        .context("failed to create OCSP client")?;
    let verifier = GpuLocalVerifier::new(&rim_store, &ocsp_client)
        .context("failed to create GPU local verifier")?;
    let policy = EvidencePolicy::builder()
        .verify_rim_signature(true)
        .verify_rim_cert_chain(true)
        .build()
        .context("failed to create evidence policy")?;
    let result = verifier
        .verify(&evidence, &policy)
        .context("failed to verify GPU evidence")?;

    let claims_json =
        serde_json::from_str(&result.claims_json()?).context("failed to parse claims JSON")?;
    let detached_eat_json = result
        .eat_json()
        .ok()
        .map(|raw| serde_json::from_str(&raw).context("failed to parse detached EAT JSON"))
        .transpose()?;

    Ok(Response {
        vendor: None,
        evidence_format: None,
        evidence_json: None,
        claims_json: Some(claims_json),
        detached_eat_json,
    })
}
