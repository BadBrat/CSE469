#!/usr/bin/env python3
import os
import sys
import struct
import uuid
import hashlib
from datetime import datetime, timezone
try:
    from Crypto.Cipher import AES
except ImportError:
    print("> Required crypto library not found", file=sys.stderr)
    sys.exit(1)

# AES-128 encryption key (16 bytes) hard-coded as given&#8203;:contentReference[oaicite:86]{index=86}
AES_KEY = b"R0chLi4uLi4uLi4="
cipher = AES.new(AES_KEY, AES.MODE_ECB)

def encrypt_case(case_uuid: uuid.UUID) -> bytes:
    """Encrypt a UUID into 16 bytes, return as 32-byte hex string (as bytes)."""
    enc = cipher.encrypt(case_uuid.bytes)  # 16-byte plaintext
    return enc.hex().encode('ascii')

def encrypt_item_id(item_id: int) -> bytes:
    """Encrypt a 4-byte item_id into 16 bytes, return as 32-byte hex string."""
    b4 = item_id.to_bytes(4, 'big')            # 4-byte big-endian
    block = b'\x00'*12 + b4                    # pad to 16 bytes【19†output】
    enc = cipher.encrypt(block)
    return enc.hex().encode('ascii')

def decrypt_case(hex_bytes: bytes) -> uuid.UUID:
    """Decrypt a stored 32-byte hex case_id to UUID."""
    enc = bytes.fromhex(hex_bytes.decode('ascii'))
    dec = cipher.decrypt(enc)
    return uuid.UUID(bytes=dec)

def decrypt_item_id(hex_bytes: bytes) -> int:
    """Decrypt a stored 32-byte hex item_id to integer."""
    enc = bytes.fromhex(hex_bytes.decode('ascii'))
    dec = cipher.decrypt(enc)
    return int.from_bytes(dec[-4:], 'big')

def print_line(message: str = ""):
    """Print a message line prefixed with '> ' (for stdout output)."""
    sys.stdout.write(f"> {message}\n")

def load_blocks(filepath: str):
    """Load and parse all blocks from the blockchain file into a list."""
    blocks = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return blocks
    offset = 0
    header_fmt = "32sd32s32s12s12s12sI"  # as recommended&#8203;:contentReference[oaicite:87]{index=87}
    header_size = struct.calcsize(header_fmt)
    while offset + header_size <= len(data):
        header_bytes = data[offset: offset + header_size]
        prev_hash, timestamp, case_bytes, item_bytes, state_bytes, creator_bytes, owner_bytes, data_len = \
            struct.unpack(header_fmt, header_bytes)
        offset += header_size
        data_field = data[offset: offset + data_len] if data_len > 0 else b""
        offset += data_len
        # Decode strings (strip null padding)
        state = state_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
        creator = creator_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
        owner = owner_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
        # Compute hash of this block
        block_raw = header_bytes + data_field
        block_hash = hashlib.sha256(block_raw).digest()
        # Prepare block record dict
        block = {
            "prev_hash": prev_hash,
            "timestamp": timestamp,
            "case_enc": case_bytes,
            "item_enc": item_bytes,
            "state": state,
            "creator": creator,
            "owner": owner,
            "data_len": data_len,
            "data": data_field,
            "hash": block_hash
        }
        # Decrypt identifiers if not the initial block
        if state != "INITIAL":
            try:
                block["case_id"] = decrypt_case(case_bytes)
            except Exception:
                block["case_id"] = None
            try:
                block["item_id"] = decrypt_item_id(item_bytes)
            except Exception:
                block["item_id"] = None
        else:
            block["case_id"] = None
            block["item_id"] = None
        blocks.append(block)
    return blocks

def write_initial_block(filepath: str):
    """Create the genesis block in a new blockchain file."""
    with open(filepath, "wb") as f:
        prev_hash = b'\x00' * 32
        case_field = b"0" * 32        # 32 ascii '0's for case_id&#8203;:contentReference[oaicite:88]{index=88}
        item_field = b"0" * 32        # 32 ascii '0's for item_id
        state = "INITIAL"
        creator = ""                  # 12 null bytes
        owner = ""                    # 12 null bytes
        data_bytes = b"Initial block\0"  # Data field&#8203;:contentReference[oaicite:89]{index=89}
        # Pack and write initial block
        header = struct.pack("32sd32s32s12s12s12sI",
                              prev_hash, 0.0,
                              case_field, item_field,
                              state.encode('ascii'),
                              creator.encode('ascii'),
                              owner.encode('ascii'),
                              len(data_bytes))
        f.write(header + data_bytes)

# Determine file path for blockchain data
file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")

# Fetch environment passwords (expected to be set in the environment)&#8203;:contentReference[oaicite:90]{index=90}
role_passwords = {
    "CREATOR": os.getenv("BCHOC_PASSWORD_CREATOR"),
    "POLICE": os.getenv("BCHOC_PASSWORD_POLICE"),
    "LAWYER": os.getenv("BCHOC_PASSWORD_LAWYER"),
    "ANALYST": os.getenv("BCHOC_PASSWORD_ANALYST"),
    "EXECUTIVE": os.getenv("BCHOC_PASSWORD_EXECUTIVE")
}

# Argument parsing (simple manual parsing for this script)
args = sys.argv[1:]
if not args:
    print_line("No command provided")
    sys.exit(1)
command = args[0].lower()

# Helper for password checks
def check_password(role_required=None):
    if "-p" not in args:
        return False
    # get password value following -p
    try:
        pwd = args[args.index("-p") + 1]
    except IndexError:
        pwd = ""
    if role_required == "CREATOR":
        return pwd == role_passwords["CREATOR"]
    elif role_required is None:
        # any owner role
        return pwd in (role_passwords["POLICE"], role_passwords["LAWYER"],
                       role_passwords["ANALYST"], role_passwords["EXECUTIVE"])
    else:
        # specific role check if needed (not used separately in this implementation)
        return pwd == role_passwords.get(role_required)

# Process each command
if command == "init":
    # No extra args allowed for init
    if len(args) > 1:
        print_line("Invalid parameters for init")
        sys.exit(1)
    if not os.path.exists(file_path):
        # No blockchain file: create genesis block
        write_initial_block(file_path)
        print_line("Blockchain file not found. Created INITIAL block.")
        sys.exit(0)
    # File exists: verify genesis presence
    blocks = load_blocks(file_path)
    if not blocks or blocks[0]["state"] != "INITIAL":
        print_line("Blockchain file found but INITIAL block is missing or corrupt.")
        sys.exit(1)
    else:
        print_line("Blockchain file found with INITIAL block.")
        sys.exit(0)

elif command == "add":
    # Expect -c, -i, -g, -p in args
    if "-c" not in args or "-g" not in args or "-i" not in args:
        print_line("Usage: bchoc add -c <case_id> -i <item_id>... -g <creator> -p <password>")
        sys.exit(1)
    try:
        case_idx = args.index("-c")
        case_str = args[case_idx + 1]
        creator_idx = args.index("-g")
        creator_name = args[creator_idx + 1]
    except (ValueError, IndexError):
        print_line("Missing required arguments for add")
        sys.exit(1)
    # collect all item IDs following -i flags
    item_ids = []
    for i in range(len(args)):
        if args[i] == "-i" and i + 1 < len(args):
            item_ids.append(args[i+1])
    # Validate case UUID format
    try:
        case_uuid = uuid.UUID(case_str)
    except Exception:
        print_line("Invalid case ID format")
        sys.exit(1)
    # Validate item IDs (must be integers <= 0xFFFFFFFF)
    clean_ids = []
    seen_ids = set()
    for item in item_ids:
        try:
            val = int(item)
        except ValueError:
            print_line("Invalid item ID")
            sys.exit(1)
        if val < 0 or val > 0xFFFFFFFF:
            print_line("Item ID out of range")
            sys.exit(1)
        if val in seen_ids:
            # duplicate in input
            print_line("Duplicate item ID in input")
            sys.exit(1)
        seen_ids.add(val)
        clean_ids.append(val)
    # Check creator password
    if not check_password("CREATOR"):
        print_line("Invalid password")
        sys.exit(1)
    # Ensure blockchain file exists (create INITIAL if not)
    if not os.path.exists(file_path):
        write_initial_block(file_path)
        print_line("Blockchain file not found. Created INITIAL block.")
    blocks = load_blocks(file_path)
    # Verify uniqueness of each item ID in the current chain
    existing_ids = {blk["item_id"] for blk in blocks if blk["state"] != "INITIAL"}
    for val in clean_ids:
        if val in existing_ids:
            print_line(f"Item ID {val} already exists")
            sys.exit(1)
    # Open file for appending new blocks
    try:
        f = open(file_path, "r+b")
    except Exception as e:
        print_line(f"Failed to open blockchain file: {e}")
        sys.exit(1)
    # Determine the hash of the current last block for linking
    last_block_hash = blocks[-1]["hash"] if blocks else (b'\x00'*32)
    # Move file pointer to end for appending
    f.seek(0, os.SEEK_END)
    for idx, val in enumerate(clean_ids):
        if idx == 0:
            # genesis block's prev_hash is all zeros
            prev_hash = blocks[0]["prev_hash"] if blocks else b'\x00' * 32
        else:
            prev_hash = last_block_hash

        state   = "CHECKEDIN"
        creator = creator_name[:12]
        owner   = ""          # owner must be 12 null-bytes for a fresh check-in
        data_bytes = b""
        data_len = len(data_bytes)
        # Prepare encrypted fields
        case_enc = encrypt_case(case_uuid)
        item_enc = encrypt_item_id(val)
        # Timestamp (UTC)
        ts = datetime.now(timezone.utc).timestamp()
        # Pack block header
        header_bytes = struct.pack("32sd32s32s12s12s12sI",
                                   prev_hash, ts,
                                   case_enc, item_enc,
                                   state.encode('ascii'),
                                   creator.encode('ascii'),
                                   owner.encode('ascii'),
                                   data_len)
        f.write(header_bytes + data_bytes)
        # Compute this new block's hash for linking next if needed
        new_block_hash = hashlib.sha256(header_bytes + data_bytes).digest()
        last_block_hash = new_block_hash
    f.close()
    # Output result lines for each added item
    for idx, val in enumerate(clean_ids):
        print_line(f"Added item: {val}")
        print_line("Status: CHECKEDIN")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        print_line(f"Time of action: {now_iso}")
        if idx != len(clean_ids) - 1:
            print_line("")  # blank line separator if multiple
    sys.exit(0)

elif command == "checkout":
    if "-i" not in args:
        print_line("Usage: bchoc checkout -i <item_id> -p <password>")
        sys.exit(1)
    try:
        item_idx = args.index("-i")
        item_val = int(args[item_idx + 1])
    except Exception:
        print_line("Invalid item ID")
        sys.exit(1)
    # Password must be any owner role
    if not check_password():
        print_line("Invalid password")
        sys.exit(1)
    blocks = load_blocks(file_path)
    if not blocks or not any(blk["item_id"] == item_val for blk in blocks if blk["state"] != "INITIAL"):
        print_line("Item not found")
        sys.exit(1)
    # Find last record of this item
    item_blocks = [b for b in blocks if b["item_id"] == item_val]
    last_block = item_blocks[-1]
    if last_block["state"] != "CHECKEDIN":
        print_line(f"Item {item_val} is not checked in")
        sys.exit(1)
    case_uuid = last_block["case_id"]
    # Determine roles from password
    pwd = args[args.index("-p") + 1] if "-p" in args else ""
    role = None
    for r, pw in role_passwords.items():
        if r != "CREATOR" and pw == pwd:
            role = r  # identify the role performing the checkout
            break
    # Append CHECKEDOUT block
    prev_hash = blocks[-1]["hash"]
    state = "CHECKEDOUT"
    # The previous owner (evidence manager) can be found from the last CHECKEDIN block of this item
    first_block = next(b for b in item_blocks if b["state"] == "CHECKEDIN")
    evidence_manager = first_block["creator"] or first_block["owner"]
    evidence_manager = evidence_manager[:12]
    new_creator = evidence_manager       # person releasing it (custodian)
    new_owner = role or ""              # role of person taking it
    data_bytes = b""
    # Encrypt fields and write block
    case_enc = encrypt_case(case_uuid)
    item_enc = encrypt_item_id(item_val)
    try:
        f = open(file_path, "ab")
    except Exception as e:
        print_line(f"Failed to open blockchain file: {e}")
        sys.exit(1)
    header = struct.pack("32sd32s32s12s12s12sI",
                         prev_hash, datetime.now(timezone.utc).timestamp(),
                         case_enc, item_enc,
                         state.encode('ascii'),
                         new_creator.encode('ascii'),
                         new_owner.encode('ascii'),
                         len(data_bytes))
    f.write(header + data_bytes)
    f.close()
    # Output confirmation
    print_line(f"Case: {case_uuid}")
    print_line(f"Checked out item: {item_val}")
    print_line("Status: CHECKEDOUT")
    print_line(f"Time of action: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}")
    sys.exit(0)

elif command == "checkin":
    if "-i" not in args:
        print_line("Usage: bchoc checkin -i <item_id> -p <password>")
        sys.exit(1)
    try:
        item_idx = args.index("-i")
        item_val = int(args[item_idx + 1])
    except Exception:
        print_line("Invalid item ID")
        sys.exit(1)
    if not check_password():
        print_line("Invalid password")
        sys.exit(1)
    blocks = load_blocks(file_path)
    if not blocks or not any(blk["item_id"] == item_val for blk in blocks if blk["state"] != "INITIAL"):
        print_line("Item not found")
        sys.exit(1)
    item_blocks = [b for b in blocks if b["item_id"] == item_val]
    last_block = item_blocks[-1]
    if last_block["state"] != "CHECKEDOUT":
        print_line(f"Item {item_val} is not checked out")
        sys.exit(1)
    case_uuid = last_block["case_id"]
    # Append CHECKEDIN block (return to custody)
    



    # Link to the tip of the chain
    prev_hash = blocks[-1]["hash"]
    state     = "CHECKEDIN"

    # Figure out which role just ran `checkin -p PASSWORD`
    pwd  = args[args.index("-p") + 1]
    role = None
    for r, pw in role_passwords.items():
        if r != "CREATOR" and pw == pwd:
            role = r[:12]
            break

    # The “creator” of this new check-in block is always the original evidence manager
    first_block    = next(b for b in item_blocks if b["state"] == "CHECKEDIN")
    new_creator    = first_block["creator"][:12]

    # The “owner” of this block is the person doing the checkin (the role you just derived)
    new_owner      = (role or "").ljust(12, "\0")[:12]


    data_bytes = b""
    case_enc = encrypt_case(case_uuid)
    item_enc = encrypt_item_id(item_val)
    try:
        f = open(file_path, "ab")
    except Exception as e:
        print_line(f"Failed to open blockchain file: {e}")
        sys.exit(1)
    header = struct.pack("32sd32s32s12s12s12sI",
                         prev_hash, datetime.now(timezone.utc).timestamp(),
                         case_enc, item_enc,
                         state.encode('ascii'),
                         new_creator.encode('ascii'),
                         new_owner.encode('ascii'),
                         len(data_bytes))
    f.write(header + data_bytes)
    f.close()
    # Output
    print_line(f"Case: {case_uuid}")
    print_line(f"Checked in item: {item_val}")
    print_line("Status: CHECKEDIN")
    print_line(f"Time of action: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}")
    sys.exit(0)

elif command == "remove":
    if "-i" not in args and ("-y" not in args and "--why" not in args):
        print_line("Usage: bchoc remove -i <item_id> -y <reason> -p <password>")
        sys.exit(1)
    try:
        item_idx = args.index("-i")
        item_val = int(args[item_idx + 1])
    except Exception:
        print_line("Invalid item ID")
        sys.exit(1)
    try:
        if "-y" in args:
            reason_idx = args.index("-y")
        else:
            reason_idx = args.index("--why")
        reason_text = args[reason_idx + 1]
    except Exception:
        print_line("Removal reason not provided")
        sys.exit(1)

    # Check for valid Reason
    valid_reasons = {"DISPOSED", "DESTROYED", "RELEASED"}
    if reason_text not in valid_reasons:
        print_line("Invalid removal reason")
        sys.exit(1)

    # Only creator can remove
    if not check_password("CREATOR"):
        print_line("Invalid password")
        sys.exit(1)
    blocks = load_blocks(file_path)
    if not blocks or not any(blk["item_id"] == item_val for blk in blocks if blk["state"] != "INITIAL"):
        print_line("Item not found")
        sys.exit(1)
    item_blocks = [b for b in blocks if b["item_id"] == item_val]
    last_block = item_blocks[-1]
    if last_block["state"] != "CHECKEDIN":
        print_line(f"Item {item_val} cannot be removed now")
        sys.exit(1)
    case_uuid = last_block["case_id"]
    # Append REMOVED block
    prev_hash = blocks[-1]["hash"]
    state = "REMOVED"
    # Evidence manager (creator) executes removal
    first_block = next(b for b in item_blocks if b["state"] == "CHECKEDIN")
    evidence_manager = first_block["creator"] or first_block["owner"]
    evidence_manager = evidence_manager[:12]
    new_creator = evidence_manager
    new_owner = evidence_manager
    data_bytes = reason_text.encode('ascii') + b'\x00'
    case_enc = encrypt_case(case_uuid)
    item_enc = encrypt_item_id(item_val)
    try:
        f = open(file_path, "ab")
    except Exception as e:
        print_line(f"Failed to open blockchain file: {e}")
        sys.exit(1)
    header = struct.pack("32sd32s32s12s12s12sI",
                         prev_hash, datetime.now(timezone.utc).timestamp(),
                         case_enc, item_enc,
                         state.encode('ascii'),
                         new_creator.encode('ascii'),
                         new_owner.encode('ascii'),
                         len(data_bytes))
    f.write(header + data_bytes)
    f.close()
    # Output confirmation
    print_line(f"Removed item: {item_val}")
    print_line("Status: REMOVED")
    print_line(f"Time of action: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}")
    print_line(f"Reason: {reason_text}")
    sys.exit(0)

elif command == "show":
    # Expect a subcommand next: cases, items, history
    if len(args) < 2:
        print_line("Usage: bchoc show cases|items|history [...]")
        sys.exit(1)
    subcmd = args[1].lower()
    blocks = load_blocks(file_path)
    if subcmd == "cases":
        case_ids = []
        for blk in blocks:
            if blk["state"] == "INITIAL":
                continue
            cid = blk["case_id"]
            if cid and cid not in case_ids:
                case_ids.append(cid)
        authorized = check_password()  # any owner
        for cid in case_ids:
            if authorized:
                print_line(str(cid))
            else:
                # find encrypted form from one block of that case
                enc = None
                for blk in blocks:
                    if blk["case_id"] == cid:
                        enc = blk["case_enc"]
                        break
                if enc:
                    print_line(enc.decode('ascii'))
        sys.exit(0)
    elif subcmd == "items":
        if "-c" not in args:
            print_line("Usage: bchoc show items -c <case_id> [-p password]")
            sys.exit(1)
        try:
            case_idx = args.index("-c")
            case_filter = uuid.UUID(args[case_idx + 1])
        except Exception:
            print_line("Invalid case ID format")
            sys.exit(1)
        item_ids = []
        for blk in blocks:
            if blk["state"] == "INITIAL":
                continue
            if blk["case_id"] == case_filter and blk["item_id"] not in item_ids:
                item_ids.append(blk["item_id"])
        authorized = check_password()
        for iid in item_ids:
            if authorized:
                print_line(str(iid))
            else:
                enc = None
                for blk in blocks:
                    if blk["item_id"] == iid:
                        enc = blk["item_enc"]; break
                if enc:
                    print_line(enc.decode('ascii'))
        sys.exit(0)
    elif subcmd == "history":
        case_filter = None
        item_filter = None
        num = None
        reverse = False
        if "-c" in args:
            try:
                case_idx = args.index("-c")
                case_filter = uuid.UUID(args[case_idx + 1])
            except Exception:
                print_line("Invalid case ID")
                sys.exit(1)
        if "-i" in args:
            try:
                item_idx = args.index("-i")
                item_filter = int(args[item_idx + 1])
            except Exception:
                print_line("Invalid item ID")
                sys.exit(1)
        if "-n" in args:
            try:
                n_idx = args.index("-n")
                num = int(args[n_idx + 1])
                if num < 0:
                    num = None
            except Exception:
                print_line("Invalid number of entries")
                sys.exit(1)
        if "-r" in args:
            reverse = True
        # Gather matching entries
        history = []
        for blk in blocks:
            if blk["state"] == "INITIAL":
                continue
            if case_filter and blk["case_id"] != case_filter:
                continue
            if item_filter is not None and blk["item_id"] != item_filter:
                continue
            history.append(blk)
        if item_filter and case_filter and not history:
            print_line("No history found for given case and item")
            sys.exit(0)
        history.sort(key=lambda b: b["timestamp"])
        if reverse:
            history.reverse()
        if num is not None:
            history = history[:num] if reverse else history[:num]
        authorized = check_password()
        for idx, blk in enumerate(history):
            case_str = str(blk["case_id"]) if authorized else blk["case_enc"].decode('ascii')
            item_str = str(blk["item_id"]) if authorized else blk["item_enc"].decode('ascii')
            print_line(f"Case: {case_str}")
            print_line(f"Item: {item_str}")
            print_line(f"Action: {blk['state']}")
            ts = datetime.fromtimestamp(blk["timestamp"], tz=timezone.utc)
            print_line(f"Time: {ts.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}")
            if idx != len(history) - 1:
                print_line("")  # blank line separator
        sys.exit(0)
    else:
        print_line("Unknown show command")
        sys.exit(1)

elif command == "summary":
    if "-c" not in args:
        print_line("Usage: bchoc summary -c <case_id> [-p password]")
        sys.exit(1)
    try:
        case_idx = args.index("-c")
        case_uuid = uuid.UUID(args[case_idx + 1])
    except Exception:
        print_line("Invalid case ID format")
        sys.exit(1)
    blocks = load_blocks(file_path)
    items = {}
    for blk in blocks:
        if blk["state"] == "INITIAL":
            continue
        if blk["case_id"] != case_uuid:
            continue
        # Track each item's final state
        items.setdefault(blk["item_id"], None)
        items[blk["item_id"]] = blk["state"]
    if not items:
        print_line("Case not found or has no items")
        sys.exit(0)
    authorized = check_password()
    case_out = str(case_uuid) if authorized else encrypt_case(case_uuid).decode('ascii')
    total = len(items)
    checked_in = sum(1 for st in items.values() if st == "CHECKEDIN")
    checked_out = sum(1 for st in items.values() if st == "CHECKEDOUT")
    removed = sum(1 for st in items.values() if st == "REMOVED")
    print_line(f"Case: {case_out}")
    print_line(f"Total items: {total}")
    print_line(f"Items checked in: {checked_in}")
    print_line(f"Items checked out: {checked_out}")
    print_line(f"Items removed: {removed}")
    sys.exit(0)

elif command == "verify":
    blocks = load_blocks(file_path)
    if not blocks:
        print_line("Blockchain file not found.")
        sys.exit(1)
    total_blocks = len(blocks)
    print_line(f"Transactions in blockchain: {total_blocks}")
    state = "CLEAN"
    bad_block_hash = None
    parent_block_hash = None
    error_note = ""
    # Check genesis block
    if blocks[0]["state"] != "INITIAL":
        state = "ERROR"
        bad_block_hash = blocks[0]["hash"].hex()
        error_note = "Parent block: NOT FOUND"
    # Check for duplicate prev_hash (forks)
    prev_seen = set()
    for blk in blocks[1:]:
        prev_hex = blk["prev_hash"].hex()
        if prev_hex != "0"*64:  # skip genesis prev (all zeros) for branch check
            if prev_hex in prev_seen:
                state = "ERROR"
                bad_block_hash = blk["hash"].hex()
                parent_block_hash = prev_hex
                error_note = "Two blocks were found with the same parent."
                break
            prev_seen.add(prev_hex)
    # Check sequential linking
    if state == "CLEAN":
        for i in range(1, len(blocks)):
            curr = blocks[i]
            prev = blocks[i-1]
            if curr["prev_hash"] != prev["hash"]:
                state = "ERROR"
                # Identify bad block and message
                if curr["prev_hash"] not in [b["hash"] for b in blocks]:
                    bad_block_hash = curr["hash"].hex()
                    error_note = "Parent block: NOT FOUND"
                else:
                    bad_block_hash = prev["hash"].hex()
                    error_note = "Block contents do not match block checksum."
                break
    # Check duplicate state transitions (double check-in, check-out or remove)
    if state == "CLEAN":
        last_state = {}
        for blk in blocks[1:]:
            action = blk["state"]
            if action in ("CHECKEDIN", "CHECKEDOUT", "REMOVED"):
                item = blk["item_id"]
            # if the same action repeats for the same item → error
                if last_state.get(item) == action:
                    state = "ERROR"
                    bad_block_hash = blk["hash"].hex()
                    error_note = f"Duplicate {action} for item {item}."
                    break
                last_state[item] = action

    # Check no actions after removal
    if state == "CLEAN":
        removed_items = set()
        for blk in blocks:
            if blk["state"] == "REMOVED":
                removed_items.add(blk["item_id"])
            if blk["item_id"] in removed_items and blk["state"] not in ("INITIAL", "REMOVED"):
                state = "ERROR"
                bad_block_hash = blk["hash"].hex()
                error_note = "Item checked out or checked in after removal from chain."
                break
    # Output results
    print_line(f"State of blockchain: {state}")
    if state == "ERROR":
        print_line(f"Bad block: ")
        print_line(f"{bad_block_hash}")
        if parent_block_hash is not None:
            # parent_block_hash is a hex string if duplicate parent scenario
            if error_note.startswith("Two blocks") or error_note == "Parent block: NOT FOUND":
                # if duplicate parent, we have parent_block_hash to show
                if error_note.startswith("Two blocks"):
                    print_line("Parent block: ")
                    print_line(f"{parent_block_hash}")
                else:
                    # parent not found scenario was already noted
                    print_line("Parent block: NOT FOUND")
            # (else, for checksum mismatch, parent_block_hash unused)
        if error_note and not error_note.startswith("Parent block:"):
            print_line(error_note)
        sys.exit(1)
    else:
        sys.exit(0)
else:
    print_line("Unknown command")
    sys.exit(1)
