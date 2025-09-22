#!/usr/bin/env python3
"""
TRX Sweep Bot Flask Application - Optimized for Render Free Tier
Webhook-based TRX sweeping bot that responds to QuickNode webhook notifications
Optimized to prevent worker timeouts and memory issues on free hosting tiers
"""

import os
import hmac
import json
import logging
import base64
import time
import threading
import requests
from flask import Flask, request, jsonify
from tronpy import Tron
from tronpy.providers import HTTPProvider
from tronpy.keys import PrivateKey

# Configure simple logging with reduced verbosity for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
        app.logger.info(f"Remote Address: {request.remote_addr}")
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

# Lightweight in-memory cache with size limit to prevent memory growth
MAX_PROCESSED_TXIDS = 1000
processed_txids = set()

def validate_env_vars():
    """Validate required environment variables"""
    required_vars = ['TARGET_ADDR', 'SAFE_WALLET', 'PRIVATE_KEY', 'WEBHOOK_SECURITY_TOKEN']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)
    
    # Validate TRON addresses
    target_addr_val = os.getenv('TARGET_ADDR', '').strip()
    safe_wallet_val = os.getenv('SAFE_WALLET', '').strip()
    
    if not (target_addr_val and target_addr_val.startswith('T') and len(target_addr_val) == 34):
        logger.error(f"Invalid TARGET_ADDR format: {target_addr_val}")
        exit(1)
    
    if not (safe_wallet_val and safe_wallet_val.startswith('T') and len(safe_wallet_val) == 34):
        logger.error(f"Invalid SAFE_WALLET format: {safe_wallet_val}")
        exit(1)
    
    # Validate private key
    private_key_val = os.getenv('PRIVATE_KEY', '').strip()
    if private_key_val.startswith('0x'):
        private_key_val = private_key_val[2:]
    
    if not private_key_val or len(private_key_val) != 64:
        logger.error(f"Invalid PRIVATE_KEY format: must be 64 hex characters")
        exit(1)
    
    try:
        PrivateKey(bytes.fromhex(private_key_val))
        
        # Validate optional numeric environment variables
        min_trx_left_val = float(os.getenv('MIN_TRX_LEFT', '0.3'))
        if min_trx_left_val < 0 or min_trx_left_val > 10:
            logger.error(f"Invalid MIN_TRX_LEFT: {min_trx_left_val}. Must be between 0 and 10 TRX")
            exit(1)
        
        permission_id_val = int(os.getenv('PERMISSION_ID', '4'))
        if permission_id_val < 0 or permission_id_val > 10:
            logger.error(f"Invalid PERMISSION_ID: {permission_id_val}. Must be between 0 and 10")
            exit(1)
        
        logger.info("Environment variables validated successfully")
    except ValueError as e:
        logger.error(f"Invalid numeric environment variable: {e}")
        exit(1)
    except Exception as e:
        logger.error(f"Invalid PRIVATE_KEY: {e}")
        exit(1)

def get_balance(client_instance, address):
    """Get TRX balance for address in TRX units with timeout"""
    try:
        account_info = client_instance.get_account(address)
        balance_sun = account_info.get('balance', 0)
        balance_trx = balance_sun / 1_000_000
        return balance_trx
    except Exception as e:
        logger.error(f"Error getting balance for {address}: {e}")
        return 0

def sweep_trx_async(client_instance, p_key, t_addr, s_wallet, m_trx_left, p_id):
    """Optimized sweep function that broadcasts transaction without waiting for confirmation"""
    try:
        bot_address = p_key.public_key.to_base58check_address()
        account_info = client_instance.get_account(t_addr)
        balance_sun = account_info.get('balance', 0)
        balance_trx = balance_sun / 1_000_000
        fee_reserve_sun = int(m_trx_left * 1_000_000)
        
        if balance_sun <= (1_000_000 + fee_reserve_sun):
            logger.info(f"Balance {balance_trx:.6f} TRX <= {(1_000_000 + fee_reserve_sun) / 1_000_000:.1f} TRX threshold, no sweep needed")
            return {'success': False, 'reason': 'insufficient_balance', 'txid': None}
        
        send_amount_sun = balance_sun - fee_reserve_sun
        send_amount_trx = send_amount_sun / 1_000_000
        
        if send_amount_sun <= 0:
            logger.warning(f"Insufficient balance after fee reserve: {balance_trx:.6f} TRX")
            return {'success': False, 'reason': 'insufficient_after_fees', 'txid': None}
        
        logger.info(f"Sweeping {send_amount_trx:.6f} TRX from {t_addr} to {s_wallet}")
        
        if bot_address == t_addr:
            logger.info("Using direct control transfer")
            txn = client_instance.trx.transfer(t_addr, s_wallet, send_amount_sun).build().sign(p_key)
        else:
            logger.info("Using multi-signature transfer with active_trx permission")
            try:
                txn = client_instance.trx.transfer(t_addr, s_wallet, send_amount_sun).permission_id(p_id).build().sign(p_key)
            except Exception as perm_e:
                logger.warning(f"Permission-based transfer failed: {perm_e}")
                logger.info("Attempting standard transfer as fallback")
                txn = client_instance.trx.transfer(t_addr, s_wallet, send_amount_sun).build().sign(p_key)
        
        logger.info("Broadcasting transaction (async mode - not waiting for confirmation)")
        result = txn.broadcast()
        
        if result and hasattr(result, 'txid'):
            txid = result.txid
            logger.info(f"Transaction broadcasted successfully! TXID: {txid}")
            return {'success': True, 'reason': 'broadcasted', 'txid': txid}
        else:
            logger.error(f"Broadcast failed: {result}")
            return {'success': False, 'reason': 'broadcast_failed', 'txid': None}
            
    except Exception as e:
        logger.error(f"Error during sweep: {e}")
        return {'success': False, 'reason': 'exception', 'txid': None, 'error': str(e)}

def initialize_bot():
    """Initialize bot configuration and validate setup"""
    global client, private_key, target_addr, safe_wallet, webhook_security_token, min_trx_left, permission_id
    logger.info("Initializing TRX Sweep Bot Flask Application...")
    validate_env_vars()
    quicknode_url = os.getenv('QUICKNODE_URL', '').strip()
    target_addr = os.getenv('TARGET_ADDR', '').strip()
    safe_wallet = os.getenv('SAFE_WALLET', '').strip()
    private_key_hex = os.getenv('PRIVATE_KEY', '').strip()
    
    raw_secret = os.getenv('WEBHOOK_SECURITY_TOKEN', '')
    sanitized_secret = raw_secret.strip().lstrip('\ufeff')
    webhook_security_token = sanitized_secret
    logger.info(f"Sanitized Webhook Security Token. Original length: {len(raw_secret)}, Sanitized length: {len(webhook_security_token)}")
    logger.info(f"Sanitized Token repr(): {repr(webhook_security_token)}")

    min_trx_left = float(os.getenv('MIN_TRX_LEFT', '0.3'))
    permission_id = int(os.getenv('PERMISSION_ID', '4'))
    
    if private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]
    
    if quicknode_url:
        provider = HTTPProvider(api_key='', endpoint_uri=quicknode_url)
        client = Tron(provider=provider)
        logger.info("Using QuickNode as HTTP provider")
    else:
        client = Tron()
        logger.info("Using default Tron provider (mainnet)")
    
    private_key = PrivateKey(bytes.fromhex(private_key_hex))
    logger.info(f"Target address: {target_addr}")
    logger.info(f"Safe wallet: {safe_wallet}")
    logger.info(f"Fee reserve: {min_trx_left} TRX")
    logger.info(f"Permission ID: {permission_id}")
    logger.info("Bot initialized successfully")
    return True

# FINAL FIX: Added missing 'import hashlib'
def verify_webhook_signature(headers, payload_bytes, secret):
    """Verify QuickNode webhook signature using the official nonce + timestamp + body recipe."""
    import hashlib  # <-- THIS WAS THE MISSING LINE
    
    signature = headers.get('X-Qn-Signature')
    nonce = headers.get('X-Qn-Nonce')
    timestamp = headers.get('X-Qn-Timestamp')

    if not signature or not secret or not nonce or not timestamp:
        logger.warning("Signature, secret, nonce, or timestamp is missing for verification.")
        return False
    
    try:
        secret_bytes = secret.encode('utf-8')
        
        message_string = f"{nonce}{timestamp}{payload_bytes.decode('utf-8')}"
        message_bytes = message_string.encode('utf-8')
        
        expected_signature = hmac.new(secret_bytes, message_bytes, hashlib.sha256).hexdigest()
        
        received_signature = signature
        if received_signature.startswith('sha256='):
            received_signature = received_signature[7:]

        is_valid = hmac.compare_digest(received_signature, expected_signature)
        
        if is_valid:
            logger.info("Webhook signature verified successfully using official [nonce+timestamp+body] recipe.")
            return True
        else:
            logger.warning("!!! Webhook signature verification FAILED using official [nonce+timestamp+body] recipe !!!")
            logger.warning(f"Received Signature: {received_signature}")
            logger.warning(f"Expected Signature: {expected_signature}")
            logger.warning(f"Data signed (string): {repr(message_string)}")
            return False
        
    except Exception as e:
        logger.error(f"Error during signature verification: {e}")
        return False


def process_webhook_payload(payload_bytes):
    """Process webhook payload to detect Tron transactions to target address"""
    try:
        payload_str = payload_bytes.decode('utf-8')
        data = json.loads(payload_str)
        txid = None
        
        if 'raw_data' in data and 'contract' in data.get('raw_data', {}):
            contracts = data['raw_data'].get('contract', [])
            txid = data.get('txID')
            
            for contract in contracts:
                if contract.get('type') == 'TransferContract':
                    to_address_hex = contract.get('parameter', {}).get('value', {}).get('to_address')
                    if to_address_hex and target_addr:
                        try:
                            if to_address_hex.startswith('41'):
                                import base58
                                to_address_b58 = base58.b58encode_check(bytes.fromhex(to_address_hex)).decode('utf-8')
                                if to_address_b58 == target_addr:
                                    logger.info(f"Tron TRX transfer detected to target address: {target_addr}, txid: {txid}")
                                    return {'detected': True, 'txid': txid}
                            elif to_address_hex == target_addr:
                                logger.info(f"Tron TRX transfer detected to target address: {target_addr}, txid: {txid}")
                                return {'detected': True, 'txid': txid}
                        except Exception as addr_e:
                            logger.warning(f"Error converting Tron address: {addr_e}")
        
        return {'detected': False, 'txid': None}
        
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.info("Payload was not a valid JSON object, likely a check request. Ignoring.")
        return {'detected': False, 'txid': None}
    except Exception as e:
        logger.error(f"Error processing webhook payload: {e}")
        return {'detected': False, 'txid': None}

def manage_processed_txids_cache(txid):
    """Manage the processed transaction IDs cache to prevent memory growth"""
    global processed_txids
    if txid:
        processed_txids.add(txid)
        if len(processed_txids) > MAX_PROCESSED_TXIDS:
            txids_list = list(processed_txids)
            processed_txids = set(txids_list[len(txids_list)//2:])
            logger.info(f"Processed TXIDs cache trimmed to {len(processed_txids)} entries")

def keep_alive():
    """A function to be run in a background thread to keep the Render instance alive."""
    while True:
        try:
            render_url = os.getenv('RENDER_EXTERNAL_URL', f"http://127.0.0.1:{os.getenv('PORT', 5000  )}")
            if render_url:
                health_url = f"{render_url}/health"
                logger.info(f"Keep-alive: Pinging {health_url}")
                requests.get(health_url, timeout=10)
        except Exception as e:
            logger.error(f"Keep-alive: An unexpected error occurred: {e}")
        time.sleep(600)

# Flask Routes
@app.route('/', methods=['GET'])
def status():
    """Status endpoint showing bot configuration and health"""
    if not client or not target_addr or not safe_wallet:
        return jsonify({'status': 'error', 'message': 'Bot not properly initialized', 'initialized': False}), 500
    current_balance = get_balance(client, target_addr)
    return jsonify({
        'status': 'active', 'message': 'TRX Sweep Bot is running', 'initialized': True,
        'target_address': target_addr, 'safe_wallet': safe_wallet, 'current_balance_trx': current_balance,
        'min_trx_left': min_trx_left, 'permission_id': permission_id, 'processed_txids_count': len(processed_txids)
    })

@app.route('/health', methods=['GET'])
def health():
    """Simple health check endpoint for monitoring services"""
    return jsonify({
        'status': 'healthy', 'timestamp': time.time(), 'optimization': 'memory_managed',
        'version': '1.7' # Final version with the bug fix
    })

@app.route('/webhook-v2', methods=['POST', 'GET'])
def webhook():
    """Webhook endpoint for receiving transaction notifications."""
    if request.method == 'GET':
        return jsonify({"status": "ok", "message": "Webhook endpoint is active. Use POST for data."}), 200
    
    try:
        payload_bytes = request.get_data()
        
        if webhook_security_token:
            if not verify_webhook_signature(request.headers, payload_bytes, webhook_security_token):
                return jsonify({'error': 'Invalid signature'}), 401
        else:
            logger.warning("Webhook security token not configured - accepting all requests")
        
        result = process_webhook_payload(payload_bytes)
        
        if result['detected']:
            txid = result['txid']
            if txid and txid in processed_txids:
                logger.info(f"Transaction {txid} already processed, skipping")
                return jsonify({'status': 'skipped', 'message': 'Transaction already processed', 'txid': txid})
            
            logger.info(f"Attempting to sweep TRX from {target_addr}")
            sweep_result = sweep_trx_async(client, private_key, target_addr, safe_wallet, min_trx_left, permission_id)
            manage_processed_txids_cache(txid)
            
            if sweep_result['success']:
                return jsonify({'status': 'success', 'message': 'TRX sweep transaction broadcasted', 'txid': sweep_result['txid']})
            else:
                return jsonify({'status': 'no_action', 'message': f'Sweep not performed: {sweep_result["reason"]}'})
        else:
            return jsonify({'status': 'ok', 'message': 'Check request successful or no relevant transaction detected'})
            
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/manual-sweep', methods=['POST'])
def manual_sweep():
    """Manual sweep endpoint for testing purposes."""
    try:
        logger.info("Manual sweep requested")
        if not client or not target_addr or not safe_wallet:
            return jsonify({'status': 'error', 'message': 'Bot not properly initialized'}), 500
        
        sweep_result = sweep_trx_async(client, private_key, target_addr, safe_wallet, min_trx_left, permission_id)
        
        if sweep_result['success']:
            return jsonify({'status': 'success', 'message': 'Manual TRX sweep transaction broadcasted', 'txid': sweep_result['txid']})
        else:
            return jsonify({'status': 'no_action', 'message': f'Sweep not performed: {sweep_result["reason"]}'})
            
    except Exception as e:
        logger.error(f"Error in manual sweep: {e}")
        return jsonify({'error': str(e)}), 500

# Initialize bot and start keep-alive thread
try:
    if initialize_bot():
        keep_alive_thread = threading.Thread(name='keep-alive', target=keep_alive)
        keep_alive_thread.daemon = True
        keep_alive_thread.start()
        logger.info("Keep-alive background thread started.")
except Exception as e:
    logger.error(f"Failed to initialize bot: {e}")

if __name__ == "__main__":
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting Flask TRX Sweep Bot on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
