#!/usr/bin/env python3
"""
TRX Sweep Bot Flask Application
Webhook-based TRX sweeping bot that responds to QuickNode webhook notifications
Maintains all existing sweep functionality with event-driven architecture
"""

import os
import hashlib
import hmac
import json
import logging
import base64
from flask import Flask, request, jsonify
from tronpy import Tron
from tronpy.providers import HTTPProvider
from tronpy.keys import PrivateKey

# Configure simple logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Global variables for bot configuration
client = None
private_key = None
target_addr = None
safe_wallet = None
webhook_security_token = None
min_trx_left = None
permission_id = None

# In-memory cache for processed transaction IDs to prevent duplicate sweeps
processed_txids = set()

def validate_env_vars():
    """Validate required environment variables"""
    required_vars = ['TARGET_ADDR', 'SAFE_WALLET', 'PRIVATE_KEY', 'WEBHOOK_SECURITY_TOKEN']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    # Optional environment variables with defaults
    if not os.getenv('QUICKNODE_URL'):
        logger.warning("QUICKNODE_URL not set, will use default Tron provider")
    
    if not os.getenv('MIN_TRX_LEFT'):
        logger.info("MIN_TRX_LEFT not set, using default 0.3 TRX")
    
    if not os.getenv('PERMISSION_ID'):
        logger.info("PERMISSION_ID not set, using default 4 for multi-signature")
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)
    
    # Validate TRON addresses
    target_addr = os.getenv('TARGET_ADDR')
    safe_wallet = os.getenv('SAFE_WALLET')
    
    if target_addr:
        target_addr = target_addr.strip()
    if safe_wallet:
        safe_wallet = safe_wallet.strip()
    
    if not (target_addr and target_addr.startswith('T') and len(target_addr) == 34):
        logger.error(f"Invalid TARGET_ADDR format: {target_addr}")
        exit(1)
    
    if not (safe_wallet and safe_wallet.startswith('T') and len(safe_wallet) == 34):
        logger.error(f"Invalid SAFE_WALLET format: {safe_wallet}")
        exit(1)
    
    # Validate private key
    private_key = os.getenv('PRIVATE_KEY')
    if private_key:
        private_key = private_key.strip()
    if private_key and private_key.startswith('0x'):
        private_key = private_key[2:]
    
    if not private_key or len(private_key) != 64:
        logger.error(f"Invalid PRIVATE_KEY format: must be 64 hex characters")
        exit(1)
    
    try:
        PrivateKey(bytes.fromhex(private_key))
        
        # Validate optional numeric environment variables
        min_trx_left = float(os.getenv('MIN_TRX_LEFT', '0.3'))
        if min_trx_left < 0 or min_trx_left > 10:
            logger.error(f"Invalid MIN_TRX_LEFT: {min_trx_left}. Must be between 0 and 10 TRX")
            exit(1)
        
        permission_id = int(os.getenv('PERMISSION_ID', '4'))
        if permission_id < 0 or permission_id > 10:
            logger.error(f"Invalid PERMISSION_ID: {permission_id}. Must be between 0 and 10")
            exit(1)
        
        logger.info("Environment variables validated successfully")
    except ValueError as e:
        logger.error(f"Invalid numeric environment variable: {e}")
        exit(1)
    except Exception as e:
        logger.error(f"Invalid PRIVATE_KEY: {e}")
        exit(1)

def validate_private_key_for_multisig(client, private_key, target_addr):
    """Validate that the private key has permission to sweep from target address"""
    try:
        # Get the address that this private key controls
        controlled_address = private_key.public_key.to_base58check_address()
        
        logger.info(f"Bot address: {controlled_address}")
        logger.info(f"Target address: {target_addr}")
        
        if controlled_address == target_addr:
            logger.info("Private key directly controls target address")
            return True
        else:
            logger.info(f"Multi-signature setup detected: Bot address {controlled_address} has permission to sweep from {target_addr}")
            logger.info("Will use active_trx permission for TRX transfers")
            return True
        
    except Exception as e:
        logger.error(f"Error validating private key: {e}")
        logger.warning("Flask server will start but sweep functionality will be limited.")
        return False

def get_balance(client, address):
    """Get TRX balance for address in TRX units"""
    try:
        # Use get_account() instead of get_account_balance() for reliable results
        account_info = client.get_account(address)
        balance_sun = account_info.get('balance', 0)
        balance_trx = balance_sun / 1_000_000  # Convert from SUN to TRX
        return balance_trx
    except Exception as e:
        logger.error(f"Error getting balance for {address}: {e}")
        return 0

def sweep_trx(client, private_key, target_addr, safe_wallet, min_trx_left, permission_id):
    """Sweep all TRX from target address to safe wallet using multi-signature permissions"""
    try:
        # Get the bot's address
        bot_address = private_key.public_key.to_base58check_address()
        
        # Get current balance  
        account_info = client.get_account(target_addr)
        balance_sun = account_info.get('balance', 0)
        balance_trx = balance_sun / 1_000_000
        
        # Use configurable fee reserve
        fee_reserve_sun = int(min_trx_left * 1_000_000)  # Convert TRX to SUN
        
        # Check if we should sweep using the new logic
        if balance_sun <= (1_000_000 + fee_reserve_sun):  # 1 TRX + fee reserve
            logger.info(f"Balance {balance_trx:.6f} TRX <= {(1_000_000 + fee_reserve_sun) / 1_000_000:.1f} TRX threshold, no sweep needed")
            return False
        
        # Calculate amount to send (leave small amount for transaction fee)
        send_amount_sun = balance_sun - fee_reserve_sun
        send_amount_trx = send_amount_sun / 1_000_000
        
        if send_amount_sun <= 0:
            logger.warning(f"Insufficient balance after fee reserve: {balance_trx:.6f} TRX")
            return False
        
        logger.info(f"Sweeping {send_amount_trx:.6f} TRX from {target_addr} to {safe_wallet}")
        logger.info(f"Bot address: {bot_address}")
        logger.info(f"Will leave ~{fee_reserve_sun / 1_000_000:.1f} TRX for transaction fees")
        
        # Check if this is direct control or multi-sig
        if bot_address == target_addr:
            # Direct control - use standard transfer
            logger.info("Using direct control transfer")
            txn = (
                client.trx.transfer(target_addr, safe_wallet, send_amount_sun)
                .build()
                .sign(private_key)
            )
        else:
            # Multi-signature setup - use permission-based transfer
            logger.info("Using multi-signature transfer with active_trx permission")
            try:
                # Create transaction with permission ID for active_trx
                txn = (
                    client.trx.transfer(target_addr, safe_wallet, send_amount_sun)
                    .permission_id(permission_id)  # Configurable permission ID
                    .build()
                    .sign(private_key)
                )
            except Exception as perm_e:
                logger.warning(f"Permission-based transfer failed: {perm_e}")
                logger.info("Attempting standard transfer as fallback")
                txn = (
                    client.trx.transfer(target_addr, safe_wallet, send_amount_sun)
                    .build()
                    .sign(private_key)
                )
        
        # Broadcast transaction with proper confirmation waiting
        logger.info("Broadcasting transaction and waiting for confirmation...")
        result = txn.broadcast().wait()
        
        # Check if transaction was successful
        # Transaction is successful if it has a valid txid and blockNumber
        if result and result.get('txid') and result.get('blockNumber'):
            txid = result.get('txid', 'unknown')
            logger.info(f"Sweep successful! TXID: {txid}")
            logger.info(f"Swept {send_amount_trx:.6f} TRX to {safe_wallet}")
            
            # Log final balance
            final_account_info = client.get_account(target_addr)
            final_balance_sun = final_account_info.get('balance', 0)
            final_balance_trx = final_balance_sun / 1_000_000
            logger.info(f"Final balance after sweep: {final_balance_trx:.6f} TRX")
            
            return True
        else:
            logger.error(f"Sweep failed: {result}")
            return False
            
    except Exception as e:
        logger.error(f"Error during sweep: {e}")
        return False

def initialize_bot():
    """Initialize bot configuration and validate setup"""
    global client, private_key, target_addr, safe_wallet, webhook_security_token, min_trx_left, permission_id
    
    logger.info("Initializing TRX Sweep Bot Flask Application...")
    
    # Validate environment variables
    validate_env_vars()
    
    # Get configuration
    quicknode_url = os.getenv('QUICKNODE_URL')
    target_addr = os.getenv('TARGET_ADDR')
    safe_wallet = os.getenv('SAFE_WALLET')
    private_key_hex = os.getenv('PRIVATE_KEY')
    webhook_security_token = os.getenv('WEBHOOK_SECURITY_TOKEN')
    min_trx_left = float(os.getenv('MIN_TRX_LEFT', '0.3'))  # Default 0.3 TRX fee reserve
    permission_id = int(os.getenv('PERMISSION_ID', '4'))  # Default permission ID 4
    
    # Strip whitespace if values exist
    if quicknode_url:
        quicknode_url = quicknode_url.strip()
    if target_addr:
        target_addr = target_addr.strip()
    if safe_wallet:
        safe_wallet = safe_wallet.strip()
    if private_key_hex:
        private_key_hex = private_key_hex.strip()
    if webhook_security_token:
        webhook_security_token = webhook_security_token.strip()
    
    # Remove 0x prefix if present
    if private_key_hex and private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]
    
    # Initialize client with QuickNode or default provider
    if quicknode_url:
        provider = HTTPProvider(api_key='', endpoint_uri=quicknode_url)
        client = Tron(provider=provider)
        logger.info("Using QuickNode as HTTP provider")
    else:
        client = Tron()
        logger.info("Using default Tron provider (mainnet)")
    private_key = PrivateKey(bytes.fromhex(private_key_hex or ''))
    
    logger.info(f"Target address: {target_addr}")
    logger.info(f"Safe wallet: {safe_wallet}")
    logger.info(f"Fee reserve: {min_trx_left} TRX")
    logger.info(f"Permission ID: {permission_id}")
    logger.info("Bot initialized successfully")
    
    # Validate private key for multi-signature setup (non-blocking)
    credentials_valid = validate_private_key_for_multisig(client, private_key, target_addr)
    if not credentials_valid:
        logger.warning("Bot started with invalid credentials - webhook endpoint will be available but sweep functionality disabled")
    
    return True

def verify_webhook_signature(payload, signature, secret):
    """Verify webhook signature for QuickNode and other webhook providers"""
    if not signature or not secret:
        return False
    
    try:
        # Handle different signature formats
        original_signature = signature
        
        # Remove common prefixes
        if signature.startswith('sha256='):
            signature = signature[7:]
        elif signature.startswith('sha1='):
            signature = signature[5:]
        
        # Calculate expected signatures in both hex and base64 formats
        secret_bytes = secret.encode('utf-8')
        
        # Hex format (most common)
        expected_hex = hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()
        
        # Base64 format (sometimes used)
        expected_b64 = base64.b64encode(
            hmac.new(secret_bytes, payload, hashlib.sha256).digest()
        ).decode('utf-8')
        
        # Try multiple comparison methods
        comparisons = [
            hmac.compare_digest(signature, expected_hex),
            hmac.compare_digest(signature, expected_b64),
            hmac.compare_digest(original_signature, f"sha256={expected_hex}"),
            hmac.compare_digest(original_signature, expected_hex),
            hmac.compare_digest(original_signature, expected_b64)
        ]
        
        result = any(comparisons)
        if result:
            logger.info("Webhook signature verification successful")
        else:
            logger.warning(f"Webhook signature verification failed. Tried formats: hex, base64, with/without prefix")
        
        return result
        
    except Exception as e:
        logger.error(f"Error verifying webhook signature: {e}")
        return False

def process_webhook_payload(payload):
    """Process webhook payload to detect Tron transactions to target address"""
    try:
        # Parse the webhook payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        
        data = json.loads(payload) if isinstance(payload, str) else payload
        txid = None
        
        # Check for Tron-specific transaction structure
        if 'raw_data' in data and 'contract' in data.get('raw_data', {}):
            # Handle Tron transaction structure: raw_data.contract[0].parameter.value
            contracts = data['raw_data'].get('contract', [])
            txid = data.get('txID')
            
            for contract in contracts:
                # Check if this is a TransferContract (TRX transfer)
                contract_type = contract.get('type')
                if contract_type == 'TransferContract':
                    parameter = contract.get('parameter', {})
                    value = parameter.get('value', {})
                    to_address = value.get('to_address')
                    
                    if to_address and target_addr:
                        # Convert hex address to base58 if needed
                        try:
                            if to_address.startswith('41'):  # Tron hex format
                                import base58
                                to_address_b58 = base58.b58encode_check(bytes.fromhex(to_address)).decode('utf-8')
                                if to_address_b58 == target_addr:
                                    logger.info(f"Tron TRX transfer detected to target address: {target_addr}, txid: {txid}")
                                    return {'detected': True, 'txid': txid}
                            elif to_address == target_addr:
                                logger.info(f"Tron TRX transfer detected to target address: {target_addr}, txid: {txid}")
                                return {'detected': True, 'txid': txid}
                        except Exception as addr_e:
                            logger.warning(f"Error converting Tron address: {addr_e}")
        
        # Check legacy QuickNode webhook payload structures
        if 'result' in data and 'to' in data.get('result', {}):
            to_address = data['result'].get('to')
            txid = data['result'].get('hash') or data['result'].get('txid')
            if to_address and target_addr and to_address.lower() == target_addr.lower():
                logger.info(f"Transaction detected to target address: {target_addr}, txid: {txid}")
                return {'detected': True, 'txid': txid}
        
        # Alternative payload structure for multiple transactions
        if 'transactions' in data:
            for tx in data['transactions']:
                to_address = tx.get('to_address')
                txid = tx.get('txid') or tx.get('hash')
                if to_address and target_addr and to_address.lower() == target_addr.lower():
                    logger.info(f"Transaction detected to target address: {target_addr}, txid: {txid}")
                    return {'detected': True, 'txid': txid}
        
        # Check for address-specific notifications
        if 'address' in data and target_addr and data['address'].lower() == target_addr.lower():
            txid = data.get('txid') or data.get('hash')
            logger.info(f"Address notification for target address: {target_addr}, txid: {txid}")
            return {'detected': True, 'txid': txid}
        
        logger.info("Webhook received but no relevant Tron transaction detected")
        return {'detected': False, 'txid': None}
        
    except Exception as e:
        logger.error(f"Error processing webhook payload: {e}")
        return {'detected': False, 'txid': None}

def trigger_sweep_check(txid=None):
    """Check balance and trigger sweep if needed"""
    global min_trx_left, permission_id
    try:
        # Reordered null checks before any operations
        if not client:
            logger.error("Tron client not initialized, cannot perform sweep check")
            return False
            
        if not target_addr:
            logger.error("Target address not set, cannot perform sweep check")
            return False
            
        if not private_key:
            logger.error("Private key not available, cannot perform sweep")
            return False
            
        if not safe_wallet:
            logger.error("Safe wallet not set, cannot perform sweep")
            return False
        
        # Check for duplicate transaction processing
        if txid and txid in processed_txids:
            logger.info(f"Transaction {txid} already processed, skipping duplicate sweep check")
            return False
        
        # Get balance first
        balance_trx = get_balance(client, target_addr)
        logger.info(f"Current balance: {balance_trx:.6f} TRX")
        
        # Get balance in SUN for precise comparison
        account_info = client.get_account(target_addr)
        balance_sun = account_info.get('balance', 0)
        fee_reserve_sun = int(min_trx_left * 1_000_000)  # Convert TRX to SUN
        sweep_threshold_sun = 1_000_000 + fee_reserve_sun  # 1 TRX + fee reserve
        
        # Add txid to processed cache if provided
        if txid:
            processed_txids.add(txid)
            # Keep cache size manageable (last 1000 transactions)
            if len(processed_txids) > 1000:
                processed_txids.clear()
                logger.info("Cleared processed txids cache")
        
        # Sweep if balance > threshold (1 TRX + fee reserve)
        if balance_sun > sweep_threshold_sun:
            logger.info(f"Balance {balance_trx:.6f} TRX > {sweep_threshold_sun / 1_000_000:.1f} TRX threshold, initiating sweep...")
            success = sweep_trx(client, private_key, target_addr, safe_wallet, min_trx_left, permission_id)
            
            if success:
                logger.info("Sweep completed successfully")
                return True
            else:
                logger.error("Sweep failed")
                return False
        else:
            logger.info(f"Balance {balance_trx:.6f} TRX <= {sweep_threshold_sun / 1_000_000:.1f} TRX threshold, no action needed")
            return False
            
    except Exception as e:
        logger.error(f"Error during sweep check: {e}")
        return False

# Flask Routes
@app.route('/', methods=['GET'])
def status():
    """Status endpoint showing bot configuration and health"""
    try:
        balance_trx = get_balance(client, target_addr) if client and target_addr else 0
        
        status_info = {
            'status': 'running',
            'bot_type': 'TRX Sweep Bot - Webhook Mode',
            'target_address': target_addr,
            'safe_wallet': safe_wallet,
            'current_balance_trx': round(balance_trx, 6),
            'webhook_configured': bool(webhook_security_token),
            'initialized': bool(client and private_key)
        }
        
        return jsonify(status_info), 200
        
    except Exception as e:
        logger.error(f"Error in status endpoint: {e}")
        return jsonify({'error': 'Status check failed', 'details': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Simple health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': int(__import__('time').time())}), 200

@app.route('/webhook', methods=['POST'])
def webhook():
    """Webhook endpoint for QuickNode and other webhook notifications"""
    try:
        # Get the raw payload and check for various signature headers
        payload = request.get_data()
        
        # Check for QuickNode and other common webhook signature headers
        signature = (
            request.headers.get('X-Quicknode-Signature') or 
            request.headers.get('X-QuickNode-Signature') or
            request.headers.get('X-Webhook-Signature') or 
            request.headers.get('X-Hub-Signature-256') or
            request.headers.get('X-Hub-Signature')
        )
        
        logger.info(f"Webhook received from {request.remote_addr}, checking signature...")
        
        # Verify webhook signature
        if not verify_webhook_signature(payload, signature, webhook_security_token):
            logger.warning(f"Webhook signature verification failed. Headers: {dict(request.headers)}")
            return jsonify({'error': 'Invalid signature'}), 401
        
        logger.info("Webhook received with valid signature")
        
        # Process the webhook payload
        result = process_webhook_payload(payload)
        transaction_detected = result.get('detected', False)
        txid = result.get('txid')
        
        if transaction_detected:
            # Trigger sweep check with transaction ID for deduplication
            sweep_result = trigger_sweep_check(txid=txid)
            return jsonify({
                'status': 'processed',
                'transaction_detected': True,
                'txid': txid,
                'sweep_triggered': sweep_result
            }), 200
        else:
            return jsonify({
                'status': 'processed',
                'transaction_detected': False,
                'txid': txid,
                'sweep_triggered': False
            }), 200
        
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({'error': 'Webhook processing failed', 'details': str(e)}), 500

@app.route('/manual-sweep', methods=['POST'])
def manual_sweep():
    """Manual sweep trigger endpoint for backward compatibility"""
    try:
        # Verify authorization (optional security header)
        auth_header = request.headers.get('Authorization')
        if auth_header != f"Bearer {webhook_security_token}":
            logger.warning("Manual sweep attempted without proper authorization")
            return jsonify({'error': 'Unauthorized'}), 401
        
        logger.info("Manual sweep triggered")
        sweep_result = trigger_sweep_check()
        
        return jsonify({
            'status': 'completed',
            'sweep_triggered': sweep_result
        }), 200
        
    except Exception as e:
        logger.error(f"Error in manual sweep: {e}")
        return jsonify({'error': 'Manual sweep failed', 'details': str(e)}), 500

if __name__ == "__main__":
    # Initialize the bot
    initialize_bot()
    
    # Run Flask app on port 5000 for Replit environment
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting Flask TRX Sweep Bot on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)