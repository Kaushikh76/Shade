"use client";
import { usePrivy } from "@privy-io/react-auth";
import { useCallback } from "react";

// Returns a getter for the current Privy access token (sent as Bearer to the API).
export function useAccessToken(): () => Promise<string | null> {
  const { getAccessToken, authenticated } = usePrivy();
  return useCallback(async () => (authenticated ? await getAccessToken() : null), [authenticated, getAccessToken]);
}
