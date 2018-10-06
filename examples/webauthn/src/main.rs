#![feature(plugin, decl_macro, proc_macro_non_items)]
#![plugin(rocket_codegen)]

extern crate base64;
extern crate rand;
extern crate ring;

extern crate rocket_contrib;
#[macro_use]
extern crate rocket;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate url;
extern crate url_serde;

#[cfg(feature = "trust_anchor_util")]
extern crate untrusted;

#[cfg(any(feature = "std", feature = "trust_anchor_util"))]
extern crate webpki;

extern crate der_parser;

use der_parser::parse_der;

#[cfg(feature = "trust_anchor_util")]
static ALL_SIGALGS: &'static [&'static webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA1,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384
];

use rocket::http::{Cookie, Cookies};
use rocket::response::Redirect;
use rocket_contrib::Json;
use rocket_contrib::{static_files::StaticFiles, Template};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_cbor::{ObjectKey, Value};

#[derive(Serialize)]
struct TemplateContext {}

#[derive(Serialize)]
struct RegistrationContext {
    challenge: String,
    user_handle: String,
}

#[derive(Deserialize, Debug)]
struct ClientDataJSON {
    challenge: String,
    // Firefox provides clientExtensions, Chrome does not. In either case, they are optional.
    //clientExtensions: ClientExtensions,

    // Firefox provides the hashAlgorithm, Chrome does not.
    // It appears that everyone is using SHA-256, so it's not a big problem.
    //#[serde(rename = "hashAlgorithm")]
    //hash_algorithm: String,

    #[serde(with = "url_serde")]
    origin: url::Url,
    #[serde(rename = "type")]
    webauthn_type: String,
}

#[derive(Deserialize, Debug)]
struct Response {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

#[derive(Deserialize, Debug)]
struct PublicKeyCredential {
    #[serde(rename = "rawId")]
    raw_id: String,
    id: String,
    response: Response,
    #[serde(rename = "type")]
    key_type: String,
}

#[get("/")]
fn index(mut cookies: Cookies) -> Template {
    let challenge = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .collect::<String>();
    // From the spec:
    // "It is RECOMMENDED to let the user handle be 64 random bytes,
    // and store this value in the user’s account."
    // https://w3c.github.io/webauthn/#user-handle
    let user_handle = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .collect::<String>();

    cookies.add_private(Cookie::new("challenge", challenge.clone()));
    let context = RegistrationContext {
        challenge: challenge,
        user_handle: user_handle,
    };
    Template::render("index", &context)
}

#[post("/register", format = "json", data = "<pubkeycred>")]
fn register_new_credential(
    mut cookies: Cookies,
    pubkeycred: Json<PublicKeyCredential>,
) -> Result<Redirect, String> {
    // We will go through the flow described here:
    // https://www.w3.org/TR/webauthn/#registering-a-new-credential
    // step-by-step.
    // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.

    let json_text = base64::decode(&pubkeycred.response.client_data_json).unwrap();

    // 2. Let C, the client data claimed as collected during the credential creation,
    // be the result of running an implementation-specific JSON parser on JSONtext.

    let c: ClientDataJSON = serde_json::from_slice(&json_text).unwrap();

    // 3. Verify that the value of C.type is webauthn.create.

    if c.webauthn_type != "webauthn.create" {
        println!("webauthn_type = {}", c.webauthn_type);
        return Err(
            "The response has been tampered with; the type should be 'webauthn.create'".to_string(),
        );
    }

    // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.

    let server_challenge = &cookies.get_private("challenge").unwrap();
    let server_challenge = server_challenge.value();
    let returned_challenge = base64::decode(&c.challenge).unwrap();
    let returned_challenge = String::from_utf8(returned_challenge).unwrap();

    if returned_challenge != server_challenge {
        println!("Server challenge  : {}", server_challenge);
        println!("Returned challenge: {}", returned_challenge);
        return Err("The server and returned challenge do not match!".to_string());
    }

    // We no longer need the challenge cookie after verifying the challenge.
    cookies.remove_private(Cookie::named("challenge"));

    // Is setting a private cookie here the correct action? It there's no way that a user could change it, so I suspect it's secure.
    // However, it feels like using a cookie is not really in the spirit of the workflow.

    // 5. Verify that the value of C.origin matches the Relying Party's origin.
    // This code only verifies localhost. Should a production hostname go in Rocket.toml?
    if c.origin.scheme() != "https" {
        if c.origin.host() != Some(url::Host::Domain("localhost")) {
            return Err("In non-secure contexts, the domain must be localhost.".to_string());
        }
    }

    // 6. Verify that the value of C.tokenBinding.status matches the state of Token Binding
    //    for the TLS connection over which the assertion was obtained.
    //    If Token Binding was used on that TLS connection,
    //    also verify that C.tokenBinding.id matches the base64url
    //    encoding of the Token Binding ID for the connection.

    // Since we are on localhost, we do not have tokenBinding data in the client response.
    if c.origin.scheme() == "https" {
        return Err("https has not been tested in this example. Token binding is not checked over non-tls connections.".to_string());
    }

    // 7. Compute the hash of response.clientDataJSON using SHA-256.

    let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &json_text);

    // 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure
    //    to obtain the attestation statement format fmt, the authenticator data authData,
    //    and the attestation statement attStmt.

    // Some heroics do go into deserializing this record; suggestions for improvements are welcome.
    let attestation_object = base64::decode(&pubkeycred.response.attestation_object).unwrap();
    let attestation_object: Value = serde_cbor::de::from_slice(&attestation_object).unwrap();
    let attestation_map = attestation_object.as_object().unwrap();

    let fmt = &attestation_map[&ObjectKey::String("fmt".to_string())];
    let fmt = fmt.as_string().unwrap();

    // The authenticator data is defined here: https://www.w3.org/TR/webauthn/#authenticator-data
    let auth_data = &attestation_map[&ObjectKey::String("authData".to_string())];
    let auth_data = auth_data.as_bytes().unwrap();

    // "The authenticator data structure is a byte array of 37 bytes or more"
    assert!(auth_data.len() >= 37);

    let attestation_statement = &attestation_map[&ObjectKey::String("attStmt".to_string())];

    let attestation_statement = attestation_statement.as_object().unwrap();
    let sig = &attestation_statement[&ObjectKey::String("sig".to_string())];
    let sig = sig.as_bytes().unwrap();

    let x5c = &attestation_statement[&ObjectKey::String("x5c".to_string())];
    // "x5c: The elements of this array contain attestnCert and its certificate chain
    //  each encoded in X.509 format.
    //  The attestation certificate attestnCert MUST be the first element in the array.""
    assert!(x5c.as_array().unwrap().len() >= 1);
    let attestn_cert = &x5c.as_array().unwrap()[0].as_bytes().unwrap();


    // 9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.

    let computed_rp_id_hash = ring::digest::digest(&ring::digest::SHA256, b"localhost");

    // The first 32 bytes of the auth_data are the rpIDHash:
    let returned_rp_id_hash = &auth_data[0..32];

    if computed_rp_id_hash.as_ref() != returned_rp_id_hash {
        println!("Computed hash: {:?}", computed_rp_id_hash.as_ref());
        println!("Returned hash: {:?}", returned_rp_id_hash);
        return Err("Computed relying party id hash does not match value returned.".to_string());
    }

    // 10. Verify that the User Present bit of the flags in authData is set.

    let flags = auth_data[32];
    let user_present = flags & 0b0000_0001;

    if user_present == 0b0000_0000 {
        println!("User is not present!");
        return Err("User is not present as the user_present flag is not set.".to_string());
    }

    // 11. If user verification is required for this registration,
    //     verify that the User Verified bit of the flags in authData is set.

    // In our registration flow, userVerification is only set to 'preferred'.
    // I was unable to complete the workflow with userVerification set to 'required', as the browser did nothing and timed out.

    // 12. Verify that the values of the client extension outputs in clientExtensionResults
    //     and the authenticator extension outputs in the extensions in authData are as expected,
    //     considering the client extension input values that were given as the extensions option in the create() call.

    // There is no clientExtension fields in any browser I have tested. This field is optional, so no action is required.

    // 13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt
    //     against the set of supported WebAuthn Attestation Statement Format Identifier values.

    if fmt != "fido-u2f" {
        return Err("Only fido-u2f attestation has been tested in this flow.".to_string());
    }

    // 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
    //     by using the attestation statement format fmt’s verification procedure given attStmt,
    //     authData and the hash of the serialized client data computed in step 7.

    let parsed = parse_der(attestn_cert).unwrap();
    println!("Parsed attestation cert: {:?}", parsed);

    let ee_input = untrusted::Input::from(attestn_cert);
    let cert = webpki::EndEntityCert::from(ee_input).unwrap();

    // 15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys)
    //     for that attestation type and attestation statement format fmt, from a trusted source or from policy

    Ok(Redirect::to("/"))
}

fn rocket() -> rocket::Rocket {
    rocket::ignite()
        .mount("/", routes![index, register_new_credential])
        .mount("/", StaticFiles::from("static/"))
        .attach(Template::fairing())
}

fn main() {
    rocket().launch();
}
