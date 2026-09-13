import { describe, it, expect, vi } from 'vitest'
import { apiClient } from '../client'
import { resumeOAuthTransaction, getOAuthConsent, postOAuthDecision } from '../oauth'
vi.mock('../client', () => ({ apiClient: { post: vi.fn().mockResolvedValue({data:{}}), get: vi.fn().mockResolvedValue({data:{}}) } }))
describe('OAuth 同源协议路径', () => {
 it('绕过普通 API 的 /api/v1 前缀', async () => {
  await resumeOAuthTransaction('transaction')
  await getOAuthConsent('transaction')
  await postOAuthDecision({transaction_id:'transaction',decision:'approve',csrf:'csrf'})
  for (const call of vi.mocked(apiClient.post).mock.calls) expect(call[2]?.baseURL).toBe('/')
  expect(vi.mocked(apiClient.get).mock.calls[0][1]?.baseURL).toBe('/')
 })
})
