#!/usr/bin/env python3
"""
TRX Sweep Bot Flask Application - Optimized for Render Free Tier
Webhook-based TRX sweeping bot that responds to Tatum webhook notifications.
Uses a reliable RPC to prevent rate-limiting and is optimized for performance.
Version: 2.3
"""

import os
import hmac
import json
import logging
import hashlib
import time
import threading
import requests
from flask import Flask, request, jsonify
from tronpy import Tron
from tronpy.providers import HTTPProvider
from tronpy.keys import PrivateKey
from logging import getLogger

# Configure simple logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# --- START OF "BLACK BOX RECORDER" ---
@app.before_request
def log_request_info():
    """Log incoming request details for debugging."""
    try:
        app.logger.info(f"--- Incoming Request ---")
        app.logger.info(f"Method: {request.method}")
        app.logger.info(f"Path: {request.full_path}")
        headers = {k: v for k, v in request.headers.items()}
        app.logger.info(f"Headers: {headers}")
        data = request.get_data()
        if data:
            try:
                app.logger.info(f"Body (decoded): {data.decode('utf-8')}")
            except UnicodeDecodeError:
                app.logger.info(f"Body (binary/non-UTF-8): {data}")
        else:
            app.logger.info("Body: (empty)")
        app.logger.info(f"--- End of Request ---")
    except Exception as e:
        app.logger.error(f"Error in before_request logger: {e}")
# --- END OF "BLACK BOX RECORDER" ---

# Global variables for bot configuration
client = None
private_key = None
target_addr = None
safe_wallet = None
webhook_security_token = None
min_trx_left = None
permission_id = None

# In-memory cache for processed transaction IDs
MAX_PROCESSED_TXIDS = 1000
processed_txids = set()

def validate_env_vars():
    """Validate required environment variables"""
    required_vars = ['TARGET_ADDR', 'SAFE_WALLET', 'PRIVATE_KEY', 'WEBHOOK_SECURITY_TOKEN']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)
    
    try:
        target_addr_val = os.getenv('TARGET_ADDR', '').strip()
        if not (target_addr_val.startswith('T') and len(target_addr_val) == 34):
            raise ValueError(f"Invalid TARGET_ADDR format: {target_addr_val}")

        safe_wallet_val = os.getenv('SAFE_WALLET', '').strip()
        if not (safe_wallet_val.startswith('T') and len(safe_wallet_val) == 34):
            raise ValueError(f"Invalid SAFE_WALLET format: {safe_wallet_val}")

        private_key_val = os.getenv('PRIVATE_KEY', '').strip().lstrip('0x')
        if len(private_key_val) != 64:
            raise ValueError("Invalid PRIVATE_KEY format: must be 64 hex characters")
        PrivateKey(bytes.fromhex(private_key_val))

        float(os.getenv('MIN_TRX_LEFT', '0.3'))
        int(os.getenv('PERMISSION_ID', '4'))
        
        logger.info("Environment variables validated successfully")
    except Exception as e:
        logger.error(f"Environment variable validation failed: {e}")
        exit(1)

def get_balance(client_instance, address):
    """Get TRX balance for address in TRX units"""
    try:
        account_info = client_instance.get_account(address)
        balance_sun = account_info.get('balance', 0)
        return balance_sun / 1_000_000
    except Exception as e:
        logger.error(f"Error getting balance for {address}: {e}")
        return 0

def sweep_trx_async(client_instance, p_key, t_addr, s_wallet, m_trx_left, p_id):
    """Optimized sweep function that broadcasts transaction without waiting for confirmation"""
    try:
        balance_sun = int(get_balance(client_instance, t_addr) * 1_000_000)
        fee_reserve_sun = int(m_trx_left * 1_000_000)
        
        if balance_sun <= (1_000_000 + fee_reserve_sun):
            return {'success': False, 'reason': 'insufficient_balance'}
        
        send_amount_sun = balance_sun - fee_reserve_sun
        if send_amount_sun <= 0:
            return {'success': False, 'reason': 'insufficient_after_fees'}
        
        logger.info(f"Sweeping {send_amount_sun / 1_000_000:.6f} TRX from {t_addr} to {s_wallet}")
        
        bot_address = p_key.public_key.to_base58check_address()
        if bot_address == t_addr:
            txn = client_instance.trx.transfer(t_addr, s_wallet, send_amount_sun).build().sign(p_key)
        else:
            txn = client_instance.trx.transfer(t_addr, s_wallet, send_amount_sun).permission_id(p_id).build().sign(p_key)
        
        result = txn.broadcast()
        
        if hasattr(result, 'txid'):
            logger.info(f"Transaction broadcasted successfully! TXID: {result.txid}")
            return {'success': True, 'txid': result.txid}
        else:
            logger.error(f"Broadcast failed: {result}")
            return {'success': False, 'reason': 'broadcast_failed'}
            
    except Exception as e:
        logger.error(f"Error during sweep: {e}")
        return {'success': False, 'reason': str(e)}

def initialize_bot():
    """Initialize bot configuration and Tron client"""
    global client, private_key, target_addr, safe_wallet, webhook_security_token, min_trx_left, permission_id
    logger.info("Initializing TRX Sweep Bot for Tatum...")
    validate_env_vars()
    
    target_addr = os.getenv('TARGET_ADDR').strip()
    safe_wallet = os.getenv('SAFE_WALLET').strip()
    private_key_hex = os.getenv('PRIVATE_KEY').strip().lstrip('0x')
    webhook_security_token = os.getenv('WEBHOOK_SECURITY_TOKEN').strip()
    min_trx_left = float(os.getenv('MIN_TRX_LEFT', '0.3'))
    permission_id = int(os.getenv('PERMISSION_ID', '4'))
    
    tatum_api_key = webhook_security_token
    tron_rpc_url = f"https://api.tatum.io/v3/blockchain/node/tron/{tatum_api_key}"
    provider = HTTPProvider(endpoint_uri=tron_rpc_url )
    client = Tron(provider=provider)
    
    private_key = PrivateKey(bytes.fromhex(private_key_hex))
    logger.info(f"Bot initialized successfully. Using Tatum RPC for Tron connections.")
    logger.info(f"Target address: {target_addr}")

def verify_webhook_signature(headers, payload_bytes, secret):
    """Verify Tatum webhook signature."""
    signature = headers.get('x-payload-signature')
    if not signature:
        logger.warning("Webhook verification failed: 'x-payload-signature' header missing.")
        return False

    try:
        secret_bytes = secret.encode('utf-8')
        expected_signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()

        if hmac.compare_digest(signature, expected_signature):
            logger.info("Tatum webhook signature verified successfully.")
            return True
        else:
            logger.warning(f"!!! Tatum webhook signature verification FAILED !!!")
            return False
    except Exception as e:
        logger.error(f"Error during signature verification: {e}")
        return False

def process_webhook_payload(payload_bytes):
    """Process Tatum webhook payload for ADDRESS_EVENT on Tron."""
    try:
        data = json.loads(payload_bytes.decode('utf-8'))
        
        is_tron_mainnet = data.get('chain') == 'tron-mainnet'
        is_target_address = data.get('address') == target_addr
        is_incoming = float(data.get('amount', '0')) > 0
        
        if is_tron_mainnet and is_target_address and is_incoming:
            tx_id = data.get('txId')
            logger.info(f"Tatum: Incoming TRX transfer detected to target address, txid: {tx_id}")
            return {'detected': True, 'txid': tx_id}
        
        if data.get('subscriptionType') == 'ADDRESS_EVENT':
             return {'detected': False, 'reason': 'test_notification'}

        return {'detected': False, 'reason': 'not_relevant'}
    except Exception as e:
        logger.error(f"Error processing Tatum webhook payload: {e}")
        return {'detected': False, 'reason': 'payload_error'}

def manage_processed_txids_cache(txid):
    """Manage the processed transaction IDs cache"""
    if txid:
        processed_txids.add(txid)
        if len(processed_txids) > MAX_PROCESSED_TXIDS:
            oldest_txids = list(processed_txids)[:len(processed_txids) - (MAX_PROCESSED_TXIDS // 2)]
            for old_txid in oldest_txids:
                processed_txids.remove(old_txid)
            logger.info(f"Processed TXIDs cache trimmed.")

def keep_alive():
    """Pings the app's health endpoint to keep the Render instance alive."""
    while True:
        time.sleep(600)
        try:
            render_url = os.getenv('RENDER_EXTERNAL_URL')
            if render_url:
                health_url = f"{render_url}/health"
                logger.info(f"Keep-alive: Pinging {health_url}")
                requests.get(health_url, timeout=10)
        except Exception as e:
            logger.error(f"Keep-alive: An unexpected error occurred: {e}")

# --- Flask Routes ---
@app.route('/', methods=['GET'])
def status():
    if not client:
        return jsonify({'status': 'error', 'message': 'Bot not initialized'}), 500
    return jsonify({
        'status': 'active', 'message': 'TRX Sweep Bot is running (Tatum Mode)',
        'target_address': target_addr, 'current_balance_trx': get_balance(client, target_addr)
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'timestamp': time.time()})

@app.route('/webhook-v2', methods=['POST', 'GET'])
def webhook():
    if request.method == 'GET':
        return jsonify({"status": "ok", "message": "Webhook endpoint is active. Use POST for data."})
    
    payload_bytes = request.get_data()
    if not webhook_security_token or not verify_webhook_signature(request.headers, payload_bytes, webhook_security_token):
        return jsonify({'error': 'Invalid signature'}), 401
    
    result = process_webhook_payload(payload_bytes)
    if result.get('detected'):
        txid = result['txid']
        if txid in processed_txids:
            return jsonify({'status': 'skipped', 'message': 'Transaction already processed'})
        
        sweep_result = sweep_trx_async(client, private_key, target_addr, safe_wallet, min_trx_left, permission_id)
        if sweep_result['success']:
            manage_processed_txids_cache(txid)
            return jsonify({'status': 'success', 'message': 'Sweep transaction broadcasted', 'txid': sweep_result['txid']})
        else:
            return jsonify({'status': 'no_action', 'message': f'Sweep not performed: {sweep_result["reason"]}'})
    else:
        return jsonify({'status': 'ok', 'message': result.get('reason', 'No action taken')})

# --- App Initialization ---
try:
    initialize_bot()
    keep_alive_thread = threading.Thread(name='keep-alive', target=keep_alive, daemon=True)
    keep_alive_thread.start()
except Exception as e:
    logger.critical(f"FATAL: Failed to initialize bot. Error: {e}")

if __name__ == "__main__":
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
