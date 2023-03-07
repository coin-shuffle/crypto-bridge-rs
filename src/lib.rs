use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

use open_fastrlp::{Encodable};
use futures::executor;
use ethers::utils::hex;
use ethers_core::utils::keccak256;
use ethers_signers::{LocalWallet, Signer};
use rsa::pkcs1::{DecodeRsaPublicKey, DecodeRsaPrivateKey};
use rsa::{RsaPublicKey, RsaPrivateKey};

use coin_shuffle_core::rsa::{encode_by_chunks, decode_by_chunks};

#[repr(u8)]
pub enum RsaError {
    InvalidMsg = 1,
    InvalidNonce = 2,
    InvalidPem = 3,
    FailedToEncrypt = 4,
    FailedToDecrypt = 5,
    InvalidKey = 6,
    FailedToSign = 7,
}

fn get_string_repr(err: RsaError) -> *mut c_char {
    CString::new(String::from_utf8([err as u8].to_vec()).unwrap()).unwrap().into_raw()
}

#[no_mangle]
pub extern fn rust_encrypt(
    _msg: *const c_char,
    _nonce: *const c_char,
    _pem: *const c_char,
) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(_msg) };
    let plaintext = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(_nonce) };
    let nonce_str = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidNonce),
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(_pem) };
    let pem = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidPem),
        Ok(string) => string,
    };

    let msg = match hex::decode(plaintext) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };

    let pem_str = std::str::from_utf8(pem.as_bytes()).unwrap();
    let pub_key = match RsaPublicKey::from_pkcs1_pem(pem_str) {
        Err(_) => return get_string_repr(RsaError::InvalidPem),
        Ok(key) => key,
    };
    let nonce = match hex::decode(nonce_str) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };

    let encrpt_res = match encode_by_chunks(msg, pub_key, nonce) {
        Err(_) => return get_string_repr(RsaError::FailedToEncrypt),
        Ok(result) => result,
    };

    CString::new(hex::encode(encrpt_res.encoded_msg)).unwrap().into_raw()
}

#[no_mangle]
pub extern fn rust_decrypt(
    _msg: *const c_char,
    _pem: *const c_char,
) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(_msg) };
    let plaintext = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(_pem) };
    let pem = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidPem),
        Ok(string) => string,
    };

    let msg = match hex::decode(plaintext) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };

    let pem_str = std::str::from_utf8(pem.as_bytes()).unwrap();
    let private_key = match RsaPrivateKey::from_pkcs1_pem(pem_str) {
        Err(_) => return get_string_repr(RsaError::InvalidPem),
        Ok(key) => key,
    };
    
    let decrpt_res = match decode_by_chunks(msg, private_key) {
        Err(_) => return get_string_repr(RsaError::FailedToDecrypt),
        Ok(result) => result,
    };

    CString::new(hex::encode(decrpt_res)).unwrap().into_raw()
}

#[no_mangle]
pub extern fn rust_sign(
    _msg: *const c_char,
    _key: *const c_char
) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(_msg) };
    let plaintext = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(string) => string.as_bytes().to_vec(),
    };

    let msg = match hex::decode(plaintext) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };


    let c_str = unsafe { CStr::from_ptr(_key) };
    let hexkey = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidKey),
        Ok(string) => string,
    };

    let key = match hex::decode(hexkey) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };

    let private_key = match LocalWallet::from_bytes(key.as_slice()) {
        Err(_) => return get_string_repr(RsaError::InvalidKey),
        Ok(prv_key) => prv_key,
    };


    let signature = match executor::block_on(private_key.sign_message(msg)) {
        Err(_) => return get_string_repr(RsaError::FailedToSign),
        Ok(result) => result,
    };

    let mut encoded_signature = vec![];

    signature.encode(&mut encoded_signature);

    CString::new(hex::encode(encoded_signature.to_vec())).unwrap().into_raw()
}

#[no_mangle]
pub extern fn rust_tx_sign(
    _msg: *const c_char,
    _key: *const c_char
) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(_msg) };
    let plaintext = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(string) => string.as_bytes().to_vec(),
    };

    let msg = match hex::decode(plaintext) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };


    let c_str = unsafe { CStr::from_ptr(_key) };
    let hexkey = match c_str.to_str() {
        Err(_) => return get_string_repr(RsaError::InvalidKey),
        Ok(string) => string,
    };

    let key = match hex::decode(hexkey) {
        Err(_) => return get_string_repr(RsaError::InvalidMsg),
        Ok(data) => data,
    };

    let private_key = match LocalWallet::from_bytes(key.as_slice()) {
        Err(_) => return get_string_repr(RsaError::InvalidKey),
        Ok(prv_key) => prv_key,
    };

    let signature = match executor::block_on(private_key.sign_message(keccak256(msg))) {
        Err(_) => return get_string_repr(RsaError::FailedToSign),
        Ok(result) => result,
    };

    CString::new(hex::encode(signature.to_vec())).unwrap().into_raw()
}

#[no_mangle]
pub extern fn rust_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {return}
        CString::from_raw(s)
    };
}
