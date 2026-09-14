<template>
  <AuthLayout>
    <div class="space-y-6">
      <div class="text-center">
        <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
          授权确认
        </h2>
        <p class="mt-2 text-sm text-gray-500 dark:text-dark-400">
          应用正在请求访问你的账户
        </p>
      </div>

      <div v-if="errorMessage" class="rounded-md bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/30 dark:text-red-300">
        {{ errorMessage }}
      </div>

      <div v-if="loading" class="py-8 text-center text-sm text-gray-500 dark:text-dark-400">
        正在加载授权信息…
      </div>

      <div v-else-if="consent" class="space-y-5">
        <div class="rounded-lg border border-gray-200 p-4 dark:border-dark-700">
          <p class="text-sm text-gray-500 dark:text-dark-400">请求访问的应用</p>
          <p class="mt-1 font-medium text-gray-900 dark:text-white">{{ clientDisplayName }}</p>
          <p v-if="clientDisplayName !== consent.client_id" class="mt-0.5 text-xs text-gray-400 dark:text-dark-500">{{ consent.client_id }}</p>
        </div>

        <div class="rounded-lg border border-gray-200 p-4 dark:border-dark-700">
          <p class="text-sm text-gray-500 dark:text-dark-400">申请的权限</p>
          <ul class="mt-2 space-y-1">
            <li
              v-for="scope in consent.scopes"
              :key="scope"
              class="text-sm text-gray-900 dark:text-white"
            >
              • {{ scopeLabel(scope) }}
            </li>
          </ul>
        </div>

        <div class="flex gap-3">
          <button
            type="button"
            class="btn btn-secondary flex-1"
            :disabled="submitting"
            @click="submit('deny')"
          >
            拒绝
          </button>
          <button
            type="button"
            class="btn btn-primary flex-1"
            :disabled="submitting"
            @click="submit('approve')"
          >
            允许
          </button>
        </div>
      </div>
    </div>
  </AuthLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { AuthLayout } from '@/components/layout'
import { useAuthStore } from '@/stores'
import {
  resumeOAuthTransaction,
  getOAuthConsent,
  postOAuthDecision,
  type OAuthConsentInfo
} from '@/api/oauth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const transactionId = computed(() => {
  const v = route.query.transaction_id
  return (Array.isArray(v) ? v[0] : v) ?? ''
})

const loading = ref<boolean>(false)
const submitting = ref<boolean>(false)
const errorMessage = ref<string>('')
const consent = ref<OAuthConsentInfo | null>(null)

// Scope -> 中文描述。与后端 OAuthServerScopes（backend/internal/service/oauth_scope.go）保持一致；
// 出现未知 scope 时降级显示原始字符串。
const SCOPE_LABELS: Record<string, string> = {
  openid: '登录身份标识',
  profile: '查看基本资料',
  email: '查看邮箱地址',
  offline_access: '保持登录状态（离线访问）',
  'balance:read': '读取账户余额',
  'usage:read': '读取用量记录',
  'tokens:read': '读取 API 令牌',
  'tokens:write': '创建和管理 API 令牌'
}

function scopeLabel(scope: string): string {
  return SCOPE_LABELS[scope] ?? scope
}

// 应用显示名：优先用后端返回的注册名，缺失时降级为 client_id 字符串。
const clientDisplayName = computed(() => {
  if (!consent.value) return ''
  return consent.value.client_name?.trim() || consent.value.client_id
})

onMounted(async () => {
  if (!transactionId.value) {
    errorMessage.value = '缺少 transaction_id 参数'
    return
  }
  // Not authenticated: hand off to the existing login flow, preserving this
  // page (with its transaction_id) as the post-login return destination.
  if (!authStore.isAuthenticated) {
    router.replace({ path: '/login', query: { redirect: route.fullPath } })
    return
  }
  await loadConsent()
})

async function loadConsent(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    // Bind the logged-in user to the pending transaction first, then fetch the
    // consent details (which include the CSRF token to echo back on submit).
    await resumeOAuthTransaction(transactionId.value)
    consent.value = await getOAuthConsent(transactionId.value)
  } catch (error: unknown) {
    errorMessage.value = extractMessage(error)
  } finally {
    loading.value = false
  }
}

async function submit(decision: 'approve' | 'deny'): Promise<void> {
  if (!consent.value) return
  submitting.value = true
  errorMessage.value = ''
  try {
    const { redirect_to } = await postOAuthDecision({
      transaction_id: transactionId.value,
      decision,
      csrf: consent.value.csrf
    })
    // Top-level navigation to the OAuth client's redirect URI (may be a
    // custom-scheme deep link such as meacowork://oauth/callback).
    window.location.href = redirect_to
  } catch (error: unknown) {
    errorMessage.value = extractMessage(error)
    submitting.value = false
  }
}

function extractMessage(error: unknown): string {
  const err = error as { message?: string }
  return err?.message || '操作失败，请重试'
}
</script>
