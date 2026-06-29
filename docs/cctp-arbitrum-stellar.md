# CCTP Arbitrum Sepolia To Stellar Testnet

The inbound route is Arbitrum Sepolia USDC -> Circle CCTP V2 -> Stellar Testnet CctpForwarder -> ShadeVault.

## Locked Addresses

- Arbitrum Sepolia domain: `3`
- Stellar domain: `27`
- Arbitrum Sepolia USDC: `0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d`
- Arbitrum Sepolia TokenMessengerV2: `0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA`
- Arbitrum Sepolia MessageTransmitterV2: `0xE737e5cEBEEBa77EFE34D4aa090756590b1CE275`
- Stellar Testnet CctpForwarder: `CA66Q2WFBND6V4UEB7RD4SAXSVIWMD6RA4X3U32ELVFGXV5PJK4T4VSZ`
- Stellar Testnet MessageTransmitter: `CBJ6MTCKKZG73PMDZCJMSFRD7DQEMI4FKDH7CGDSV4W6FHCRBCQAVVJY`
- Stellar Testnet TokenMessengerMinter: `CDNG7HXAPBWICI2E3AUBP3YZWZELJLYSB6F5CC7WLDTLTHVM74SLRTHP`
- Stellar Testnet USDC: `USDC-GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`

## Burn Arguments

For `depositForBurnWithHook` on Arbitrum Sepolia:

- `destinationDomain`: `27`
- `mintRecipient`: raw 32-byte payload decoded from Stellar CctpForwarder `C...` contract strkey
- `destinationCaller`: same raw 32-byte payload as `mintRecipient`
- `burnToken`: Arbitrum Sepolia USDC
- `hookData`: 24 zero bytes, `uint32_be(0)`, `uint32_be(len(forwardRecipient))`, UTF-8 bytes of ShadeVault contract strkey

## Invariants

- Burn must be blocked before transaction submission if the destination domain is not `27`.
- Burn must be blocked if the configured CctpForwarder is not a valid Stellar contract strkey.
- Burn must be blocked if `mintRecipient` and `destinationCaller` are not both exactly the forwarder bytes32.
- Hook data must be decoded before burn and must contain the intended ShadeVault contract ID.
- CCTP message amount uses six decimal subunits. Shade accounting stores both six-decimal CCTP amount and seven-decimal Stellar amount.

## Recovery

If `mint_and_forward` succeeds but note registration fails, funds should already be at ShadeVault. The relayer must persist the CCTP nonce/message, Stellar transaction hash, amount, asset, and intended commitment, then retry only `receive_cctp_deposit`/tree append. It must not re-run burn or mint.
