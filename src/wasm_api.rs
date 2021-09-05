use crate::api::{
    self, AuthPath, Com, ComNonce, Cred, IssuanceList, ZkProof, ZkProvingKey, ZkVerifyingKey,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// Sets the panic hook for web. This gives nice backtraces in the web console on panic
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

/// Returns the base64 encoding of the given serializable value
fn val_to_str<S: CanonicalSerialize>(val: &S) -> String {
    let mut buf: Vec<u8> = Vec::new();
    val.serialize(&mut buf).expect("serialization error");
    base64::encode(&buf)
}

/// Returns the object corresponding to the inputted base64-encoded bytes
fn str_to_val<D: CanonicalDeserialize>(s: &str) -> D {
    let bytes = base64::decode(s).expect("base64 decode error");
    D::deserialize(&*bytes).expect("deserialization error")
}

/// Turns the given object into its JSON encoding
fn val_to_json<S: CanonicalSerialize>(val: &S) -> JsValue {
    JsValue::from_str(&val_to_str(val))
}

/// Turns the given pair into its JSON encoding
fn pair_to_json<S: CanonicalSerialize, D: CanonicalSerialize>(val1: &S, val2: &D) -> JsValue {
    // Concatenation is done by placing a colon between strings
    let concatenation = format!("{}:{}", val_to_str(val1), val_to_str(val2));
    JsValue::from_str(&concatenation)
}

/// Turns the given JSON value into a deserialized object
fn json_to_val<D: CanonicalDeserialize>(js_val: &JsValue) -> D {
    let s = js_val.as_string().expect("expected a string JsValue");
    str_to_val(&s)
}

/// Turns the given JSON value into two deserialized objects
fn json_to_pair<D1, D2>(js_val: &JsValue) -> (D1, D2)
where
    D1: CanonicalDeserialize,
    D2: CanonicalDeserialize,
{
    // Split the concatenation at the semicolon
    let concatenation = js_val.as_string().unwrap();
    let mut parts = concatenation.split(':');

    // Parse the two semicolon-separated parts
    let val1 = str_to_val(parts.next().expect("expected first value in pair"));
    let val2 = str_to_val(parts.next().expect("expected second value in pair"));

    (val1, val2)
}

#[wasm_bindgen]
/// Initialize the environment for zeronym operations
pub fn zeronym_init() {
    // Set the panic hook for nice backtraces
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn setup_zk_proof(log_capacity: u32) -> JsValue {
    let mut rng = OsRng;

    let (pk, vk) = api::setup_zk_proof(&mut rng, log_capacity);
    let json_pk_and_vk = pair_to_json(&pk, &vk);

    json_pk_and_vk
}

#[wasm_bindgen]
pub fn cred_gen() -> JsValue {
    let mut rng = OsRng;

    let cred = Cred::gen(&mut rng);
    let json_cred = val_to_json(&cred);

    json_cred
}

#[wasm_bindgen]
pub fn cred_commit(json_cred: &JsValue) -> JsValue {
    let mut rng = OsRng;

    let cred: api::Cred = json_to_val(json_cred);

    let (com, com_nonce) = cred.commit(&mut rng).expect("cred.commit error");
    let json_com_and_comnonce = pair_to_json(&com, &com_nonce);

    json_com_and_comnonce
}

#[wasm_bindgen]
pub fn create_list(log_capacity: u32) -> JsValue {
    let global_list = IssuanceList::empty(log_capacity);
    let json_global_list = val_to_json(&global_list);

    json_global_list
}

#[wasm_bindgen]
pub fn insert_into_list(
    json_global_list: &JsValue,
    json_com_and_comnonce: &JsValue,
    first_free_idx: u64,
) -> JsValue {
    let mut global_list: IssuanceList = json_to_val(json_global_list);
    let (com, _): (api::Com, api::ComNonce) = json_to_pair(json_com_and_comnonce);

    global_list.insert(first_free_idx, &com);
    let json_updated_global_list = val_to_json(&global_list);

    json_updated_global_list
}

#[wasm_bindgen]
pub fn get_path(
    json_global_list: &JsValue,
    json_com_and_comnonce: &JsValue,
    first_free_idx: u64,
) -> JsValue {
    let global_list: IssuanceList = json_to_val(json_global_list);
    let (com, _): (Com, ComNonce) = json_to_pair(json_com_and_comnonce);
    log("succesfully deseralized global_list and com");
    let auth_path = global_list
        .get_auth_path(first_free_idx, &com)
        .expect("couldn't get auth path");
    log("succesfully got auth_path from global_list");
    let json_auth_path = val_to_json(&auth_path);
    log("succesfully serialzed auth_path");
    json_auth_path
}

#[wasm_bindgen]
pub fn get_proof(
    json_auth_path: &JsValue,
    json_pk_and_vk: &JsValue,
    json_com_and_comnonce: &JsValue,
) -> JsValue {
    let mut rng = OsRng;

    let auth_path: AuthPath = json_to_val(json_auth_path);
    log("succesfully deseralized auth_path");
    let (pk, _): (ZkProvingKey, ZkVerifyingKey) = json_to_pair(json_pk_and_vk);
    log("succesfully deseralized public key");
    let opening = json_to_pair(json_com_and_comnonce);
    log("succesfully deseralized opening");
    let membership_proof = auth_path
        .zk_prove(&mut rng, &pk, opening)
        .expect("couldn't prove membership");
    log("succesfully got membership_proof from auth_path");
    let json_membership_proof = val_to_json(&membership_proof);
    log("succesfully serialzed membership_proof");

    json_membership_proof
}

#[wasm_bindgen]
pub fn verify(
    json_global_list: &JsValue,
    json_pk_and_vk: &JsValue,
    json_membership_proof: &JsValue,
) -> bool {
    let global_list: IssuanceList = json_to_val(json_global_list);
    let (_, vk): (ZkProvingKey, ZkVerifyingKey) = json_to_pair(json_pk_and_vk);
    let membership_proof: ZkProof = json_to_val(json_membership_proof);

    let list_root = global_list.root();
    let verified = api::zk_verify(&vk, &list_root, &membership_proof);

    verified
}

#[wasm_bindgen]
pub fn randomize(json_pk_and_vk: &JsValue, json_membership_proof: &JsValue) -> JsValue {
    let mut rng = OsRng;

    let (pk, _): (ZkProvingKey, ZkVerifyingKey) = json_to_pair(json_pk_and_vk);
    let mut membership_proof: ZkProof = json_to_val(json_membership_proof);

    membership_proof.rerandomize(&mut rng, &pk);
    let json_updated_membership_proof = val_to_json(&membership_proof);

    json_updated_membership_proof
}

#[wasm_bindgen]
pub fn remove_from_list(json_global_list: &JsValue, inserted_cred_idx: u64) -> JsValue {
    let mut global_list: IssuanceList = json_to_val(json_global_list);

    global_list.remove(inserted_cred_idx);
    let json_updated_global_list = val_to_json(&global_list);

    json_updated_global_list
}
