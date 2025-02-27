import base64
import random
from eth_hash.auto import keccak
from typing import List, Dict
import json
from eth_account import Account
from eth_account.signers.local import LocalAccount

def to_bytes32(value: int) -> bytes:
    """Convert an integer to 32-byte representation."""
    return value.to_bytes(32, 'big')

def encode_leaf(address: str, amount: int) -> bytes:
    """
    Encode leaf data the same way as the Solidity contract:
    keccak256(abi.encodePacked(address, amount))
    """
    # Remove '0x' prefix and convert to bytes
    address_bytes = bytes.fromhex(address[2:].lower().zfill(40))
    amount_bytes = amount.to_bytes(32, 'big')

    # Concatenate and hash
    return keccak(address_bytes + amount_bytes)

def create_merkle_tree(claims: List[tuple[str, int]]) -> tuple:
    """
    Create a Merkle tree from a lisst of tuples of (address, amount) claims.
    Returns (root, proofs) where proofs is a dict of address -> proof
    """
    # Create leaves
    leaves = [(addr, encode_leaf(addr, amount)) for addr, amount in claims]
    leaves.sort(key=lambda x: x[1])  # Sort leaves for consistent tree

    print("\nLeaves after sorting:")
    for addr, leaf in leaves:
        print(f"Leaf: {leaf.hex()}")

    # Store proofs for each address
    proofs: Dict[str, List[bytes]] = {addr: [] for addr, _ in leaves}

    # Build tree layer by layer
    layer = [leaf for _, leaf in leaves]
    leaf_pos = {leaf: index for index, (_, leaf) in enumerate(leaves)}

    print("\nBuilding tree layers:")
    layer_num = 0
    while len(layer) > 1:
        print(f"\nLayer {layer_num}:")
        for i, node in enumerate(layer):
            print(f"Node {i}: {node.hex()}")

        next_layer = []

        # Handle pairs of nodes
        for i in range(0, len(layer), 2):
            # Calculate the range of leaves this pair covers
            start_idx = i * (2 ** layer_num)
            end_idx = min((i + 2) * (2 ** layer_num), len(leaves))
            mid = start_idx + (2 ** layer_num)  # Use layer size to determine split point

            print(f"start_idx: {start_idx}")
            print(f"end_idx: {end_idx}")


            if i + 1 >= len(layer):
                # Odd number of nodes, promote the last one to next layer
                next_layer.append(layer[i])
                print(f"Promoting odd node: {layer[i].hex()}")
                continue

            left, right = layer[i], layer[i + 1]
            if int.from_bytes(left, 'big') < int.from_bytes(right, 'big'):
                parent = keccak(left + right)
            else:
                parent = keccak(right + left)
            next_layer.append(parent)

            print(f"\nProcessing pair:")
            print(f"Left: {left.hex()}")
            print(f"Right: {right.hex()}")
            print(f"Parent: {parent.hex()}")

            # Add proof elements for all leaves under these nodes
            for addr, leaf in leaves:
                leaf_idx = leaf_pos[leaf]
                # Check if the leaf falls within this pair's range
                if start_idx <= leaf_idx < end_idx:
                    print(f"\nLeaf: {leaf.hex()}")
                    if leaf_idx < mid:
                        proofs[addr].append(right)
                        print(f"Adding right node {right.hex()}")
                    else:
                        proofs[addr].append(left)
                        print(f"Adding left node {left.hex()}")
            print(f"\n---")

        layer = next_layer
        layer_num += 1

    root = layer[0]

    print("\nFinal proofs:")
    for addr, proof in proofs.items():
        print(f"\nAddress: {addr}")
        print(f"Proof elements: {[p.hex() for p in proof]}")

    # Convert proofs to hex strings for easier handling
    hex_proofs = {
        addr: ['0x' + proof.hex() for proof in addr_proof]
        for addr, addr_proof in proofs.items()
    }

    return ('0x' + root.hex(), hex_proofs)

def verify_proof(address: str, amount: int, proof: List[str], root: str) -> bool:
    """Verify a Merkle proof."""
    node = encode_leaf(address, amount)

    for proof_element in proof:
        proof_bytes = bytes.fromhex(proof_element[2:])
        # node = keccak(node + proof_bytes)
        if int.from_bytes(node, 'big') < int.from_bytes(proof_bytes, 'big'):
            node = keccak(node + proof_bytes)
        else:
            node = keccak(proof_bytes + node)

    return '0x' + node.hex() == root.lower()

def test_all_proofs(claims, root, proofs):
    print("\nTesting all proofs:")
    for address, amount in claims:
        proof = proofs[address]
        is_valid = verify_proof(address, amount, proof, root)
        print(f"Address: {address}")
        print(f"Amount: {amount}")
        # print(f"Proof: {proof}")
        print(f"Valid: {'✓' if is_valid else '✗'}\n")

def main():
    # Example usage
    claims = []
    for _ in range(1887):
        amount = random.randint(1 * 10**15, 100 * 10**18) # Random amount between 0.001-100 ether
        account: LocalAccount = Account.create()
        claims.append((account.address, amount))

    # Generate tree and proofs
    root, proofs = create_merkle_tree(claims)
    print(f"\nMerkle root: {root}")

    # Save to file
    output = {
        "root": root,
        "claims": {
            address: {
                "account": address,
                "amount": amount,
                "proof": proofs[address],
                "proof_base64": [base64.b64encode(bytes.fromhex(p[2:])).decode('utf-8') for p in proofs[address]]
            }
            for address, amount in claims
        }
    }

    with open('merkle_proofs.json', 'w') as f:
        json.dump(output, f, indent=2)

    print("\nProofs saved to merkle_data.json")

    # Verify a proof
    index = random.randint(0, len(claims) - 1)
    test_address, test_amount = claims[index]
    test_proof = proofs[test_address]

    is_valid = verify_proof(test_address, test_amount, test_proof, root)
    print(f"\nVerification test: {'✓ Valid' if is_valid else '✗ Invalid'}")

    test_all_proofs(claims, root, proofs)

if __name__ == "__main__":
    main()
