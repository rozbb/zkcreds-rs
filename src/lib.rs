pub mod api;
mod common;
pub mod merkle_forest;
mod multishow;
mod proof_of_issuance;
mod sparse_merkle;
mod test_util;

pub type Error = Box<dyn ark_std::error::Error>;


use wasm_bindgen::prelude::*;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::{prelude::StdRng, SeedableRng};
use rand::rngs::OsRng;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn val_to_json<S: CanonicalSerialize>(val: &S) -> JsValue {
	let mut buf: Vec<u8> = Vec::new();
	match val.serialize(&mut buf) {
		Ok(_) => (),
		Err(e) => {                                                    
			panic!("serializing error {:?}", e)                
		}, 
	};
	let bytes = format!("{:?}", &buf);

	JsValue::from_str(&bytes)
}

fn val_to_json_dos<S: CanonicalSerialize, D: CanonicalSerialize>(val1: &S, val2: &D) -> JsValue {
	let mut buf1: Vec<u8> = Vec::new();
	let mut buf2: Vec<u8> = Vec::new();
	match val1.serialize(&mut buf1) {
		Ok(_) => (),
		Err(e) => {                                                    
			panic!("serializing error {:?}", e)                
		}, 
	};
	match val2.serialize(&mut buf2) {
		Ok(_) => (),
		Err(e) => {                                                    
			panic!("serializing error {:?}", e)                
		}, 
	};

	let bytes1 = format!("{:?}", &buf1);
	let bytes2 = format!("{:?}", &buf2);

	JsValue::from_str(&format!("{}:{}", bytes1, bytes2))
}



fn json_to_val<D: CanonicalDeserialize>(js_val: &JsValue) -> D {
	let bytes = js_val.as_string().unwrap();
	let buf: Vec<u8> = bytes
	.trim_start_matches('[')
	.trim_end_matches(']')
	.split(',')
	.map(|c| c.trim().parse::<u8>().unwrap())
	.collect();
	let val = match D::deserialize(&*buf) {                                                
		Ok(n) => n,                                                  
		Err(e) => {                                                    
			panic!("deserializing error {:?}", e)                
		},                                                                 
	};  

	val
}

fn json_to_val_dos<D: CanonicalDeserialize, S: CanonicalDeserialize>(js_val: &JsValue) -> (D, S) {
	let bytes = js_val.as_string().unwrap();
	let vec_of_vec: Vec<Vec<u8>> = 
    bytes.split(':')
    .map(|b| b.trim_start_matches('[')
            	.trim_end_matches(']')
            	.split(',')
            	.map(|c| c.trim().parse::<u8>().unwrap())
            	.collect())
    .collect();

	let val1 = match D::deserialize(&*vec_of_vec[0]) {                                                
		Ok(n) => n,                                                  
		Err(e) => {                                                    
			panic!("deserializing error {:?}", e)                
		},                                                                 
	};  

	let val2 = match S::deserialize(&*vec_of_vec[1]) {                                                
		Ok(n) => n,                                                  
		Err(e) => {                                                    
			panic!("deserializing error {:?}", e)                
		},                                                                 
	};  

	(val1, val2)
}


#[wasm_bindgen]
pub fn setup_zk_proof(log_capacity: u32) -> JsValue {
	log("one");
	console_error_panic_hook::set_once();
	log("two");
	let mut rng = OsRng;
	log("three");
	let (pk, vk) = api::zk_proof_setup(&mut rng, log_capacity);
	log("four");
	let json_pk_and_vk = val_to_json_dos(&pk,&vk);
	log("five");

	json_pk_and_vk
}



#[wasm_bindgen]
pub fn cred_gen() -> JsValue {
	let mut rng = StdRng::from_entropy();	
	let cred = api::Cred::gen(&mut rng);
	let json_cred = val_to_json(&cred);

	json_cred
}



#[wasm_bindgen]
pub fn cred_commit(json_cred: &JsValue) -> JsValue {
	let mut rng = StdRng::from_entropy();
	let cred: api::Cred = json_to_val(json_cred);

	let (com, com_nonce) = match cred.commit(&mut rng){
		Ok((com, com_nonce)) => (com, com_nonce),
		Err(e) => {                                                    
			panic!("cred.commit error {:?}", e)                
		},   
	};
	let json_com_and_comnonce = val_to_json_dos(&com, &com_nonce);

	json_com_and_comnonce
}

#[wasm_bindgen]
pub fn create_list(log_capacity: u32) -> JsValue {
	let global_list = api::IssuanceList::empty(log_capacity);
	let json_global_list = val_to_json(&global_list);

	json_global_list
}

#[wasm_bindgen]
pub fn insert_into_list(json_global_list: &JsValue, json_com_and_comnonce: &JsValue, first_free_idx: u64) -> JsValue {
	let mut global_list: api::IssuanceList = json_to_val(json_global_list);
	let (com, _): (api::Com, api::ComNonce) = json_to_val_dos(json_com_and_comnonce);

	global_list.insert(first_free_idx, &com);
	let json_updated_global_list = val_to_json(&global_list);

	json_updated_global_list
}

#[wasm_bindgen]
pub fn get_path(json_global_list: &JsValue, json_com_and_comnonce: &JsValue, first_free_idx: u64) -> JsValue {
	let global_list: api::IssuanceList = json_to_val(json_global_list);
	let (com, _): (api::Com, api::ComNonce) = json_to_val_dos(json_com_and_comnonce);

	let auth_path = global_list
        .get_auth_path(first_free_idx, &com)
        .expect("couldn't get auth path");
    let json_auth_path = val_to_json(&auth_path);

    json_auth_path
}

#[wasm_bindgen]
pub fn get_proof(json_auth_path: &JsValue, json_pk_and_vk: &JsValue, json_com_and_comnonce: &JsValue) -> JsValue {
	let mut rng = StdRng::from_entropy();	
	let auth_path: api::AuthPath = json_to_val(json_auth_path);
	let(pk, _): (api::ZkProvingKey, api::ZkVerifyingKey) = json_to_val_dos(json_pk_and_vk);
	let opening = json_to_val_dos(json_com_and_comnonce);

	let membership_proof = auth_path
        .zk_prove(&mut rng, &pk, opening)
        .expect("couldn't prove membership");
    let json_membership_proof = val_to_json(&membership_proof);

    json_membership_proof
}

#[wasm_bindgen]
pub fn verify(json_global_list: &JsValue, json_pk_and_vk: &JsValue, json_membership_proof: &JsValue) -> bool {
	let global_list: api::IssuanceList = json_to_val(json_global_list);
	let (_, vk): (api::ZkProvingKey, api::ZkVerifyingKey) = json_to_val_dos(json_pk_and_vk);
	let membership_proof: api::ZkProof = json_to_val(json_membership_proof);

	let list_root = global_list.root();
    let verified = api::zk_verify(&vk, &list_root, &membership_proof);

	verified
}

#[wasm_bindgen]
pub fn randomize(json_pk_and_vk: &JsValue, json_membership_proof: &JsValue)  -> JsValue {
	let mut rng = StdRng::from_entropy();	
	let(pk, _): (api::ZkProvingKey, api::ZkVerifyingKey) = json_to_val_dos(json_pk_and_vk);
	let mut membership_proof: api::ZkProof = json_to_val(json_membership_proof);

	membership_proof.rerandomize(&mut rng, &pk);
	let json_updated_membership_proof = val_to_json(&membership_proof);

	json_updated_membership_proof
}

#[wasm_bindgen]
pub fn remove_from_list(json_global_list: &JsValue, inserted_cred_idx: u64) -> JsValue {
	let mut global_list: api::IssuanceList = json_to_val(json_global_list);

	global_list.remove(inserted_cred_idx);
	let json_updated_global_list = val_to_json(&global_list);

	json_updated_global_list
}

















