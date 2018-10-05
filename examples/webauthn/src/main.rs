#![feature(plugin, decl_macro, proc_macro_non_items)]
#![plugin(rocket_codegen)]

extern crate base64;
extern crate rand;

extern crate rocket_contrib;
#[macro_use]
extern crate rocket;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate url;
extern crate url_serde;
extern crate serde_cbor;

use rocket::response::Redirect;
use rocket_contrib::Json;
use rocket_contrib::{static_files::StaticFiles, Template};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_cbor::{Value, ObjectKey, error, de};

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
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: String,
    #[serde(with = "url_serde")]
    origin: url::Url,
    #[serde(rename = "type")]
    webauthn_type: String,
}

#[derive(Deserialize, Debug)]
struct Response {
    #[serde(rename = "clientDataJSON")]
    client_data_json: ClientDataJSON,
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
fn index() -> Template {
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
    let context = RegistrationContext {
        challenge: challenge,
        user_handle: user_handle,
    };
    Template::render("index", &context)
}


#[post("/register", format = "json", data = "<pubkeycred>")]
fn register_new_credential(pubkeycred: Json<PublicKeyCredential>) -> Result<Redirect, String> {

    // We will go through the flow described here:
    // https://www.w3.org/TR/webauthn/#registering-a-new-credential
    // step-by-step.
    // 1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
    // This is already complete, as it was converted to JSON client-side.

    // 2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
    // This is already complete, and stored in pubkeycred.response.client_data_json.

    // 3. Verify that the value of C.type is webauthn.create.
    let webauth_type = &pubkeycred.response.client_data_json.webauthn_type;
    if webauth_type != "webauthn.create" {
        return Err("The response has been tampered with; the type should be 'webauthn.create'".to_string())
    }

    // 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.

    let challenge = &pubkeycred.response.client_data_json.challenge;
    println!("Challenge: {}", challenge);


    // 5. Verify that the value of C.origin matches the Relying Party's origin.
    // This code only verifies localhost, so validate
    let origin = &pubkeycred.response.client_data_json.origin;
    if origin.scheme() != "https" {
        if origin.host() != Some(url::Host::Domain("localhost")) {
            return Err("In non-secure contexts, the domain must be localhost.".to_string())
        }
    }


    // The attestationObject provided by the WebAuthentication flow is a 'concise binary object record'.
    // Some heroics do go into deserializing this record; suggestions for improvements are welcome.
    let attestation_object = base64::decode(&pubkeycred.response.attestation_object).unwrap();
    let attestation_object: error::Result<Value> = de::from_slice(&attestation_object);
    let attestation_object: Value = attestation_object.unwrap();
    let attestation_map = attestation_object.as_object().unwrap();
    println!("Attestation Map = {:?}", attestation_map);
    let fmt = &attestation_map[&ObjectKey::String("fmt".to_string())];
    let fmt = fmt.as_string().unwrap();
    println!("format: {}", fmt);

    let auth_data = &attestation_map[&ObjectKey::String("authData".to_string())];
    let auth_data = auth_data.as_bytes().unwrap();
    println!("authData: {:?}", auth_data);

    let attestation_statement = &attestation_map[&ObjectKey::String("attStmt".to_string())];

    let attestation_statement = attestation_statement.as_object().unwrap();
    let sig = &attestation_statement[&ObjectKey::String("sig".to_string())];
    let sig = sig.as_bytes().unwrap();
    println!("sig = {:?}", sig);

    let x5c = &attestation_statement[&ObjectKey::String("x5c".to_string())];
    let x5c = &x5c.as_array().unwrap()[0].as_bytes().unwrap();
    println!("x5c = {:?}", x5c);

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
