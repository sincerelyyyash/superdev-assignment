use actix_web::{web, HttpResponse, Result};
use solana_sdk::{
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;

use crate::{types::*, utils::*, ApiResponse};
use base64::{Engine as _, engine::general_purpose};

pub async fn generate_keypair() -> Result<HttpResponse> {
    let new_keypair = Keypair::new();
    let public_key = bs58::encode(new_keypair.pubkey().as_ref()).into_string();
    let private_key = bs58::encode(&new_keypair.to_bytes()).into_string();
    
    let keypair_data = KeypairResponse { 
        pubkey: public_key, 
        secret: private_key 
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(keypair_data)))
}

pub async fn create_token(
    request_data: web::Json<CreateTokenRequest>
) -> Result<HttpResponse> {
    let mint_auth_result = validate_pubkey(&request_data.mint_authority);
    let mint_authority = match mint_auth_result {
        Ok(pk) => pk,
        Err(error_msg) => {
            return Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(error_msg)))
        },
    };
    
    let mint_result = validate_pubkey(&request_data.mint);
    if let Err(error_msg) = mint_result {
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(error_msg)));
    }
    let mint_pubkey = mint_result.unwrap();
    
    let mint_instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority,
        None,
        request_data.decimals,
    );
    
    match mint_instruction {
        Ok(instruction) => {
            let account_metas: Vec<crate::types::AccountMeta> = instruction.accounts
                .iter()
                .map(|account| crate::types::AccountMeta {
                    pubkey: account.pubkey.to_string(),
                    is_signer: account.is_signer,
                    is_writable: account.is_writable,
                })
                .collect();
            
            let instruction_response = InstructionResponse {
                program_id: instruction.program_id.to_string(),
                accounts: account_metas,
                instruction_data: general_purpose::STANDARD.encode(&instruction.data),
            };
            
            Ok(HttpResponse::Ok().json(ApiResponse::success(instruction_response)))
        }
        Err(err) => {
            let error_message = format!("Failed to create instruction: {}", err);
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(error_message)))
        }
    }
}

pub async fn mint_token(
    req: web::Json<MintTokenRequest>
) -> Result<HttpResponse> {
    let mint_pubkey = match validate_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    let dest_pubkey = validate_pubkey(&req.destination);
    if dest_pubkey.is_err() {
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(dest_pubkey.unwrap_err())));
    }
    let destination = dest_pubkey.unwrap();
    
    let authority_result = validate_pubkey(&req.authority);
    let authority = match authority_result {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    let mint_to_instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination,
        &authority,
        &[],
        req.amount,
    );
    
    if let Err(err) = mint_to_instruction {
        let error_msg = format!("Failed to create mint instruction: {}", err);
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(error_msg)));
    }
    
    let inst = mint_to_instruction.unwrap();
    let account_list: Vec<crate::types::AccountMeta> = inst.accounts
        .iter()
        .map(|acc| crate::types::AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let response_data = InstructionResponse {
        program_id: inst.program_id.to_string(),
        accounts: account_list,
        instruction_data: general_purpose::STANDARD.encode(&inst.data),
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(response_data)))
}

pub async fn sign_message(
    request: web::Json<SignMessageRequest>
) -> Result<HttpResponse> {
    if request.message.is_empty() || request.secret.is_empty() {
        let error_response = ApiResponse::<()>::error("Missing required fields".to_string());
        return Ok(HttpResponse::BadRequest().json(error_response));
    }
    
    let keypair_result = validate_keypair_from_base58(&request.secret);
    let signing_keypair = match keypair_result {
        Ok(kp) => kp,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    let msg_bytes = request.message.as_bytes();
    let message_signature = signing_keypair.sign_message(msg_bytes);
    
    let sign_response = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(message_signature.as_ref()),
        public_key: bs58::encode(signing_keypair.pubkey().as_ref()).into_string(),
        message: request.message.clone(),
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(sign_response)))
}

pub async fn verify_message(
    req: web::Json<VerifyMessageRequest>
) -> Result<HttpResponse> {
    let public_key = validate_pubkey(&req.pubkey);
    if public_key.is_err() {
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(public_key.unwrap_err())));
    }
    let pubkey = public_key.unwrap();
    
    let sig_result = validate_signature_from_base64(&req.signature);
    let signature = match sig_result {
        Ok(sig) => sig,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    let message_data = req.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_data);
    
    let verify_response = VerifyMessageResponse {
        valid: is_valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(verify_response)))
}

pub async fn send_sol(
    request_body: web::Json<SendSolRequest>
) -> Result<HttpResponse> {
    let from_pubkey = validate_pubkey(&request_body.from);
    if from_pubkey.is_err() {
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(from_pubkey.unwrap_err())));
    }
    let from = from_pubkey.unwrap();
    
    let to_result = validate_pubkey(&request_body.to);
    let to = match to_result {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    if request_body.lamports == 0 {
        let error_msg = "Amount must be greater than 0".to_string();
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(error_msg)));
    }
    
    let transfer_instruction = system_instruction::transfer(&from, &to, request_body.lamports);
    
    let instruction_accounts: Vec<crate::types::AccountMeta> = transfer_instruction.accounts
        .iter()
        .map(|acc| crate::types::AccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let sol_response = InstructionResponse {
        program_id: transfer_instruction.program_id.to_string(),
        accounts: instruction_accounts,
        instruction_data: general_purpose::STANDARD.encode(&transfer_instruction.data),
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(sol_response)))
}

pub async fn send_token(
    req: web::Json<SendTokenRequest>
) -> Result<HttpResponse> {
    let destination_key = validate_pubkey(&req.destination);
    let destination = match destination_key {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    let mint_key = validate_pubkey(&req.mint);
    if mint_key.is_err() {
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(mint_key.unwrap_err())));
    }
    let mint = mint_key.unwrap();
    
    let owner_result = validate_pubkey(&req.owner);
    let owner = match owner_result {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(e))),
    };
    
    if req.amount == 0 {
        let amount_error = "Amount must be greater than 0".to_string();
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(amount_error)));
    }
    
    let source_account = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    
    let transfer_instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_account,
        &destination,
        &owner,
        &[],
        req.amount,
    );
    
    match transfer_instruction {
        Ok(inst) => {
            let accounts_meta: Vec<crate::types::AccountMeta> = inst.accounts
                .iter()
                .map(|acc| crate::types::AccountMeta {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                })
                .collect();
            
            let token_response = InstructionResponse {
                program_id: inst.program_id.to_string(),
                accounts: accounts_meta,
                instruction_data: general_purpose::STANDARD.encode(&inst.data),
            };
            
            Ok(HttpResponse::Ok().json(ApiResponse::success(token_response)))
        }
        Err(e) => {
            let transfer_error = format!("Failed to create transfer instruction: {}", e);
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(transfer_error)))
        }
    }
}