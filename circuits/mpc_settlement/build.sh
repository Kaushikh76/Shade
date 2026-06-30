#!/usr/bin/env bash
# Build the mpc_settlement Groth16 circuit.
#
# Prerequisites:
#   circom  >= 2.2.0  (https://docs.circom.io/getting-started/installation/)
#   snarkjs >= 0.7    (npm install -g snarkjs)
#   ~1-2 GB RAM for witness generation and key export
#
# The trusted-setup uses the Hermez Powers-of-Tau ceremony (2^15 = 32 768 constraints).
# This covers the mpc_settlement circuit comfortably. For production, use a circuit-
# specific phase-2 contribution ceremony before deploying the verifier contract.
#
# Usage (from repo root):
#   bash circuits/mpc_settlement/build.sh
#
# Outputs:
#   circuits/mpc_settlement/build/   — r1cs, sym, wasm
#   circuits/mpc_settlement/output/  — final.zkey, verification_key.json

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="${SCRIPT_DIR}/build"
OUTPUT="${SCRIPT_DIR}/output"
PTAU="${SCRIPT_DIR}/../../.ptau"   # shared ptau cache outside repo
PTAU_FILE="${PTAU}/hermez_final_15.ptau"
PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau"

echo "=== mpc_settlement circuit build ==="
mkdir -p "${BUILD}" "${OUTPUT}" "${PTAU}"

# ── Step 1: Compile circom → r1cs + wasm ─────────────────────────────────────
echo "[1/5] Compiling circom..."
circom "${SCRIPT_DIR}/main.circom" \
  --r1cs --wasm --sym \
  --output "${BUILD}" \
  --prime bn128

echo "      → $(du -sh "${BUILD}/main.r1cs" | cut -f1) r1cs"
echo "      → $(du -sh "${BUILD}/main_js/main.wasm" | cut -f1) wasm"

# ── Step 2: Download ptau (cached) ───────────────────────────────────────────
if [ ! -f "${PTAU_FILE}" ]; then
  echo "[2/5] Downloading hermez_final_15.ptau (~1.1 GB)..."
  curl -L -o "${PTAU_FILE}" "${PTAU_URL}"
else
  echo "[2/5] Using cached ${PTAU_FILE}"
fi

# ── Step 3: Phase-2 setup (circuit-specific zkey) ───────────────────────────
echo "[3/5] Running groth16 setup (phase-2, dev-only)..."
snarkjs groth16 setup \
  "${BUILD}/main.r1cs" \
  "${PTAU_FILE}" \
  "${OUTPUT}/main_0.zkey"

# ── Step 4: Contribute randomness (dev beacon — NOT production safe) ──────────
echo "[4/5] Applying dev beacon contribution..."
# For production: run a full multi-party computation ceremony here.
snarkjs zkey contribute \
  "${OUTPUT}/main_0.zkey" \
  "${OUTPUT}/main_final.zkey" \
  --name="Shade dev contribution $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -e="$(openssl rand -hex 64 2>/dev/null || head -c 64 /dev/urandom | xxd -p -c 256)"

# ── Step 5: Export verification key ──────────────────────────────────────────
echo "[5/5] Exporting verification key..."
snarkjs zkey export verificationkey \
  "${OUTPUT}/main_final.zkey" \
  "${OUTPUT}/main_verification_key.json"

echo ""
echo "=== Build complete ==="
echo "  WASM:  ${BUILD}/main_js/main.wasm"
echo "  ZKEY:  ${OUTPUT}/main_final.zkey"
echo "  VK:    ${OUTPUT}/main_verification_key.json"
echo ""
echo "Next steps:"
echo "  1. Deploy the verification key via circom2soroban to get the Soroban verifier contract."
echo "  2. Update the shielded_pool mpc_settle() to call the verifier with proof_bytes + pub_signals."
echo "  3. Run the full e2e: npm run mpc:rfq:e2e"
