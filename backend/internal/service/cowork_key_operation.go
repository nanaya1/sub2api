package service

import "context"

// CoworkKeyOperation 仅关联已有操作日志，保证创建结果未知时仍能找回 Key ID。
// 不承载企业授权，不限制原生用户或管理员管理 Key。
type CoworkKeyOperation struct{ Source, ExternalUserID, RequestID string }
type coworkKeyOperationContext struct{}

func WithCoworkKeyOperation(ctx context.Context, op CoworkKeyOperation) context.Context {
	return context.WithValue(ctx, coworkKeyOperationContext{}, op)
}
func CoworkKeyOperationFromContext(ctx context.Context) (CoworkKeyOperation, bool) {
	op, ok := ctx.Value(coworkKeyOperationContext{}).(CoworkKeyOperation)
	return op, ok
}
