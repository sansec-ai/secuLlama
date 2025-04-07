// 在security包中新增qos_controller.go文件
package security

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

// 动态调控配置
type QoSConfig struct {
	MaxConcurrent   int            `yaml:"maxConcurrent"`   // 最大并发请求数
	BurstLimit      int            `yaml:"burstLimit"`      // 突发流量限额
	RateLimit       rate.Limit     `yaml:"rateLimit"`       // 基础速率限制（请求/秒）
	PriorityWeights map[string]int `yaml:"priorityWeights"` // 接口权重配置
}

// 智能调控器
type QoSController struct {
	enabled           bool
	mu                sync.Mutex
	limiter           *rate.Limiter
	config            QoSConfig
	metrics           map[string]int // 接口调用指标
	currentConcurrent int            // 实时跟踪当前并发数
}

func NewQoSController(configPath ...string) *QoSController {
	// 默认配置文件路径
	defaultPath := "qos_config.yaml"

	// 如果提供了自定义路径，则使用自定义路径
	if len(configPath) > 0 && configPath[0] != "" {
		defaultPath = configPath[0]
	}

	config, ok := loadQoSConfig(defaultPath)
	if !ok {
		return &QoSController{enabled: false} // 禁用QoS
	}
	c := &QoSController{
		enabled: true,
		limiter: rate.NewLimiter(config.RateLimit, config.BurstLimit),
		config:  config,
		metrics: make(map[string]int),
	}

	// 启动自适应调整协程
	go c.adaptiveAdjustment()
	return c
}

// 配置文件加载函数
func loadQoSConfig(configPath string) (QoSConfig, bool) {

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return QoSConfig{}, false
	}

	// 读取并解析YAML配置（可根据需要切换JSON）
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("读取配置文件失败: %v", err)
		return QoSConfig{}, false
	}

	var config QoSConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Printf("解析配置文件失败: %v", err)
		return QoSConfig{}, false
	}
	return config, true
}

// 中间件入口
func (c *QoSController) TrafficControl() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !c.enabled {
			ctx.Next() // 直接放行
			return
		}
		// 实时流量分析
		path := ctx.Request.URL.Path
		c.recordMetrics(path)

		// 动态限流决策
		if !c.acquireToken(path) {
			ctx.AbortWithStatusJSON(http.StatusTooManyRequests,
				gin.H{"error": "服务繁忙，请稍后重试"})
			return
		}
		defer c.releaseToken()

		ctx.Next()
	}
}

// 核心调控逻辑
func (c *QoSController) acquireToken(path string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	slog.Info("acquireToken", "path", path, "currentConcurrent", c.currentConcurrent)

	// 先检查并发阈值
	if c.currentConcurrent >= c.config.MaxConcurrent {
		return false
	}

	// 权重优先分配
	if weight, ok := c.config.PriorityWeights[path]; ok {
		reserved := c.limiter.ReserveN(time.Now(), weight)
		if !reserved.OK() {
			return false
		}
		delay := reserved.Delay()
		if delay > 0 {
			time.Sleep(delay)
		}
		c.currentConcurrent++ // 原子性递增
		return true
	}
	return c.limiter.Allow()
}

// 令牌释放方法
func (c *QoSController) releaseToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	slog.Info("releaseToken", "currentConcurrent", c.currentConcurrent)

	if c.currentConcurrent > 0 {
		c.currentConcurrent-- // 原子性递减
	}
}

// 指标记录
func (c *QoSController) recordMetrics(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics[path]++ // ✅ 记录调用次数
}

// 自适应调整算法
func (c *QoSController) adaptiveAdjustment() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		// 根据指标动态调整
		if total := len(c.metrics); total > 1000 {
			newLimit := rate.Limit(float64(c.config.RateLimit) * 1.2)
			c.limiter.SetLimit(newLimit)
		}
		c.metrics = make(map[string]int) // 重置指标
		c.mu.Unlock()
	}
}

// 路由集成示例
/*
router.Use(
	qosController.TrafficControl(),
	security.APIKeyAuth(crypto),
)
*/
