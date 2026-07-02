import { sorobanInvoke, TESTNET } from "@shade/stellar-utils";
import { RATE_SCALE, type RateProvider } from "@shade/mpc-crypto";

// multi-asset: resolves a MatchResult.rate from Reflector (SEP-40), the same
// oracle the pool contract validates mpc_settle's proof-bound rate against
// (see shielded_pool::validate_cross_asset_rate). Proposing a rate this close
// to the on-chain check means the proof rarely gets rejected for deviation.
//
// Reflector's live testnet CEX/DEX feed (verified against
// CCYOZJCOPG34LLQQ7N24YXBM7LL62R7ONMZ3G6WZAAYPB5OYKOMJRN63) prices assets by
// ticker symbol (`Asset::Other(Symbol)`, e.g. "XLM"/"USDC"), not by Stellar
// contract address — a project's own test-issued SAC has no DEX/CEX liquidity
// to price directly. The matcher already keys intents by symbolic asset name
// (inputAsset/outputAsset, e.g. "USDC"/"XLM"), so those names are used as the
// Reflector ticker directly — no SAC-address mapping needed here.
//
// Config (env):
//   REFLECTOR_ORACLE_CONTRACT   - the Reflector oracle contract id to query.
//   STELLAR_RELAYER_SECRET      - any funded testnet key; lastprice() is a
//                                  read-only simulated call, this key just
//                                  satisfies the CLI's --source-account.

export type ReflectorRateConfig = {
  rpcUrl: string;
  passphrase: string;
  oracleContract: string;
  readerSecret: string;
};

export function loadReflectorRateConfigFromEnv(): ReflectorRateConfig | null {
  const oracleContract = process.env.REFLECTOR_ORACLE_CONTRACT;
  const readerSecret = process.env.STELLAR_RELAYER_SECRET;
  if (!oracleContract || !readerSecret) return null;
  return {
    rpcUrl: process.env.STELLAR_RPC_URL ?? TESTNET.rpcUrl,
    passphrase: process.env.STELLAR_NETWORK_PASSPHRASE ?? TESTNET.passphrase,
    oracleContract,
    readerSecret
  };
}

function reflectorLastPrice(cfg: ReflectorRateConfig, symbol: string): bigint {
  const res = sorobanInvoke({
    contractId: cfg.oracleContract,
    secret: cfg.readerSecret,
    method: "lastprice",
    args: ["--asset", JSON.stringify({ Other: symbol })],
    rpcUrl: cfg.rpcUrl,
    passphrase: cfg.passphrase,
    readOnly: true,
    retries: 2
  });
  // lastprice returns Option<PriceData>; CLI prints JSON like
  // {"price":"12345...","timestamp":"..."} or null if no price yet.
  const parsed = JSON.parse(res.returnValue) as { price?: string | number; timestamp?: string | number } | null;
  if (!parsed || parsed.price == null) {
    throw new Error(`Reflector lastprice(${symbol}) returned no data`);
  }
  return BigInt(parsed.price);
}

// Real Reflector-backed RateProvider: fetches lastprice for both assets
// (each priced in the oracle's base currency) and derives the cross rate.
// Matches shielded_pool::validate_cross_asset_rate's math exactly:
//   rate(A in B) = price_a * RATE_SCALE / price_b
export function makeReflectorRateProvider(cfg: ReflectorRateConfig): RateProvider {
  return (assetA: string, assetB: string): bigint => {
    if (assetA === assetB) return RATE_SCALE;
    const priceA = reflectorLastPrice(cfg, assetA);
    const priceB = reflectorLastPrice(cfg, assetB);
    if (priceA <= 0n || priceB <= 0n) {
      throw new Error(`Reflector returned a non-positive price for ${assetA}/${assetB}`);
    }
    return (priceA * RATE_SCALE) / priceB;
  };
}

// Fallback used when Reflector isn't configured (local/dev without a live
// oracle). Deliberately throws rather than silently defaulting to 1:1 for
// cross-asset pairs — a wrong guessed rate would just get rejected by the
// pool's on-chain deviation check anyway, so failing fast here is clearer.
// Same-asset pairs still resolve trivially (1:1 is always correct for those).
export const noRateConfiguredProvider: RateProvider = (assetA: string, assetB: string) => {
  if (assetA === assetB) return RATE_SCALE;
  throw new Error(
    `no rate provider configured for ${assetA}/${assetB} — set REFLECTOR_ORACLE_CONTRACT and STELLAR_RELAYER_SECRET`
  );
};

export function getRateProvider(): RateProvider {
  const cfg = loadReflectorRateConfigFromEnv();
  return cfg ? makeReflectorRateProvider(cfg) : noRateConfiguredProvider;
}
