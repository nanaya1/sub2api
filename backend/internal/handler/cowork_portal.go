package handler

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// CoworkPortalHandler 复用已有业务Service，内部入口不签发用户JWT。
type CoworkPortalHandler struct{ handlers *Handlers }

func NewCoworkPortalHandler(h *Handlers) *CoworkPortalHandler {
	return &CoworkPortalHandler{handlers: h}
}

type coworkPortalRequest struct {
	service.CoworkPortalIdentity
	Operation  string                 `json:"operation"`
	Parameters coworkPortalParameters `json:"parameters"`
	ReturnURL  string                 `json:"return_url"`
}

type coworkPortalParameters struct {
	RequestID       string     `json:"requestId"`
	Operation       string     `json:"operation"`
	ID              int64      `json:"id"`
	Page            int        `json:"page"`
	PageSize        int        `json:"pageSize"`
	StartDate       string     `json:"startDate"`
	EndDate         string     `json:"endDate"`
	Model           string     `json:"model"`
	APIKeyID        int64      `json:"apiKeyId"`
	Keyword         string     `json:"keyword"`
	Status          string     `json:"status"`
	Name            string     `json:"name"`
	Quota           *float64   `json:"quota"`
	RateLimit5h     *float64   `json:"rateLimit5h"`
	RateLimit1d     *float64   `json:"rateLimit1d"`
	RateLimit7d     *float64   `json:"rateLimit7d"`
	IPWhitelist     *[]string  `json:"ipWhitelist"`
	IPBlacklist     *[]string  `json:"ipBlacklist"`
	ExpiresInDays   *int       `json:"expiresInDays"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	ClearExpiration bool       `json:"clearExpiration"`
	Amount          float64    `json:"amount"`
	PaymentType     string     `json:"paymentType"`
	Code            string     `json:"code"`
}

const coworkPortalRequestKey = "cowork_portal_request"

// Authenticate 在面板按用户限流前解析可信身份，不读取客户端身份头。
func (h *CoworkPortalHandler) Authenticate(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)
	c.Header("Cache-Control", "no-store")
	var request coworkPortalRequest
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		h.fail(c, service.ErrPortalInvalid)
		return
	}
	request.Parameters.RequestID = strings.ToLower(request.Parameters.RequestID)
	if err := h.handlers.Provisioning.service.ResolvePortalIdentity(c.Request.Context(), &request.CoworkPortalIdentity); err != nil {
		h.fail(c, err)
		return
	}
	if request.Parameters.Page == 0 {
		request.Parameters.Page = 1
	}
	if request.Parameters.PageSize == 0 {
		request.Parameters.PageSize = 20
	}
	if request.Parameters.Page < 1 || request.Parameters.Page > 1000000 || request.Parameters.PageSize < 1 || request.Parameters.PageSize > 100 || len(request.Parameters.Model) > 100 || len(request.Parameters.Keyword) > 100 {
		h.fail(c, service.ErrPortalInvalid)
		return
	}
	c.Set(coworkPortalRequestKey, &request)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: request.UserID})
	c.Set(string(middleware2.ContextKeyUserRole), service.RoleUser)
	c.Next()
}

func (h *CoworkPortalHandler) Handle(c *gin.Context) {
	value, ok := c.Get(coworkPortalRequestKey)
	if !ok {
		h.fail(c, service.ErrPortalInvalid)
		return
	}
	request := value.(*coworkPortalRequest)
	c.Header("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	result, err := h.dispatch(ctx, request, c)
	if err != nil {
		h.fail(c, err)
		return
	}
	response.Success(c, result)
}

func (h *CoworkPortalHandler) dispatch(ctx context.Context, r *coworkPortalRequest, c *gin.Context) (any, error) {
	p := r.Parameters
	switch r.Operation {
	case "usage.summary", "usage.trend", "usage.page":
		location, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		start, err := time.ParseInLocation("2006-01-02", p.StartDate, location)
		if err != nil {
			return nil, service.ErrPortalInvalid
		}
		end, err := time.ParseInLocation("2006-01-02", p.EndDate, location)
		if err != nil || p.APIKeyID < 0 {
			return nil, service.ErrPortalInvalid
		}
		return h.handlers.Provisioning.service.PortalUsage(ctx, r.CoworkPortalIdentity, service.CoworkPortalUsageFilter{Start: start, End: end.AddDate(0, 0, 1), Model: p.Model, APIKeyID: p.APIKeyID, Page: p.Page, PageSize: p.PageSize}, r.Operation)
	case "key.page", "key.detail", "key.add", "key.edit", "key.editStatus", "key.remove", "key.reveal":
		return h.keys(ctx, r)
	case "wallet.detail", "recharge.options", "recharge.add", "recharge.redeem", "recharge.history", "order.page", "order.detail", "order.cancel":
		return h.payment(ctx, r, c)
	case "operation.detail":
		if p.Operation != "key.add" && p.Operation != "recharge.add" && p.Operation != "recharge.redeem" {
			return nil, service.ErrPortalInvalid
		}
		return h.handlers.Provisioning.service.PortalOperation(ctx, r.CoworkPortalIdentity, p.Operation, p.RequestID)
	default:
		return nil, service.ErrPortalInvalid
	}
}

// once 先持久化领取再执行，PENDING及未知结果从不自动过期抢占。
func (h *CoworkPortalHandler) once(ctx context.Context, r *coworkPortalRequest, execute func() (int64, any, error)) (any, error) {
	store := h.handlers.Provisioning.service
	owner, existing, err := store.ClaimPortalOperation(ctx, r.CoworkPortalIdentity, r.Operation, r.Parameters.RequestID, r)
	if err != nil {
		return nil, err
	}
	if !owner {
		if r.Operation == "key.add" {
			if existing.ResourceID == nil {
				return nil, service.ErrPortalUnconfirmed
			}
			if err := store.PortalOwnsKey(ctx, r.CoworkPortalIdentity, *existing.ResourceID); err != nil {
				return nil, err
			}
			key, err := h.handlers.APIKey.apiKeyService.GetByID(ctx, *existing.ResourceID)
			if err != nil {
				return nil, service.ErrPortalNotFound
			}
			return coworkPortalKey(key, true), nil
		}
		if r.Operation == "recharge.add" {
			var payment any
			if json.Unmarshal(existing.Payment, &payment) != nil {
				return nil, service.ErrPortalUnconfirmed
			}
			return payment, nil
		}
		return existing, nil
	}
	id, data, err := execute()
	// 即使调用者断开连接，也尽力记录完成结果；业务不会因此再次执行
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err != nil {
		if service.PortalKnownRejection(r.Operation, err) {
			if err := store.RejectPortalOperation(finish, r.CoworkPortalIdentity, r.Operation, r.Parameters.RequestID); err != nil {
				return nil, err
			}
			return nil, service.ErrPortalRejected
		}
		store.UnconfirmPortalOperation(finish, r.CoworkPortalIdentity, r.Operation, r.Parameters.RequestID)
		return nil, service.ErrPortalUnconfirmed
	}
	var payment json.RawMessage
	if r.Operation == "recharge.add" {
		payment, err = json.Marshal(data)
		if err != nil {
			return nil, service.ErrPortalUnconfirmed
		}
	}
	if err = store.CompletePortalOperation(finish, r.CoworkPortalIdentity, r.Operation, r.Parameters.RequestID, id, payment); err != nil {
		return nil, err
	}
	if r.Operation == "recharge.redeem" {
		return &service.CoworkPortalOperation{RequestID: r.Parameters.RequestID, Operation: r.Operation, Status: "COMPLETED", ResourceID: &id}, nil
	}
	return data, nil
}

func (h *CoworkPortalHandler) fail(c *gin.Context, err error) {
	// 仅返回固定错误，不把上游SQL、商户响应、兑换码或模型Key交给通用异常日志
	for _, known := range []error{service.ErrPortalNotReady, service.ErrPortalNotFound, service.ErrPortalInvalid, service.ErrPortalConflict, service.ErrPortalUnconfirmed, service.ErrPortalRejected} {
		if err == known {
			response.ErrorFrom(c, known)
			c.Abort()
			return
		}
	}
	response.ErrorWithDetails(c, 503, "model service unavailable", "PORTAL_UNAVAILABLE", nil)
	c.Abort()
}

func finitePortalLimit(value *float64) bool {
	return value == nil || (!math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= 0 && *value < 1e9)
}

// portalMutationError 只有正式业务拒绝才能判定失败，数据库或网络错误保留写入未知语义
func portalMutationError(err error) error {
	status := infraerrors.Code(err)
	if status >= 400 && status < 500 {
		return service.ErrPortalRejected
	}
	return service.ErrPortalUnconfirmed
}
