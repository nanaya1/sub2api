/**
 * First-party OAuth Authorization Server (雪浪 OAuth) API client.
 *
 * These endpoints are same-origin and protected by the JWT web session (the
 * apiClient attaches the Bearer token from localStorage). The oauth_browser and
 * oauth_csrf cookies are sent automatically by the browser (HttpOnly).
 *
 * Flow:
 *   1. The backend /oauth2/authorize 302s here with ?transaction_id=...
 *   2. POST /oauth2/resume binds the authenticated user to the transaction.
 *   3. GET  /oauth2/consent returns the client/scopes and the CSRF token.
 *   4. POST /oauth2/consent submits the decision; the response carries the
 *      final redirect URL (redirect_to) that the caller navigates to.
 */

import { apiClient } from './client'

export interface OAuthConsentInfo {
  client_id: string
  /** 注册的应用显示名；可能为空（此时降级显示 client_id）。 */
  client_name?: string
  scopes: string[]
  transaction_id: string
  csrf: string
  user_id: number
}

export interface OAuthDecisionResponse {
  redirect_to: string
}

/** Resume (bind) the authenticated user to a pending_login transaction. */
export async function resumeOAuthTransaction(transactionId: string): Promise<void> {
  await apiClient.post<{ status: string; transaction_id: string }>(
    '/oauth2/resume',
    new URLSearchParams({ transaction_id: transactionId }).toString(),
    {
      baseURL: '/',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }
  )
}

/** Fetch consent details (client, scopes, CSRF) for the verified owner. */
export async function getOAuthConsent(transactionId: string): Promise<OAuthConsentInfo> {
  const { data } = await apiClient.get<OAuthConsentInfo>('/oauth2/consent', {
    baseURL: '/',
    params: { transaction_id: transactionId }
  })
  return data
}

/**
 * Submit the consent decision. The response returns the OAuth client's redirect
 * URL (custom-scheme deep link or https) which the caller should navigate to.
 */
export async function postOAuthDecision(params: {
  transaction_id: string
  decision: 'approve' | 'deny'
  csrf: string
}): Promise<OAuthDecisionResponse> {
  const { data } = await apiClient.post<OAuthDecisionResponse>(
    '/oauth2/consent',
    new URLSearchParams({
      transaction_id: params.transaction_id,
      decision: params.decision,
      csrf: params.csrf
    }).toString(),
    {
      baseURL: '/',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }
  )
  return data
}
