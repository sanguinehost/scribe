// Payment, Credit, and Subscription Types
// This file consolidates all payment-related types for the frontend

import type { PlanType } from '$lib/types';

// Re-export PlanType for convenience
export type { PlanType };

// ============================================================================
// Credit System Types
// ============================================================================

export interface CreditBalance {
	balance: number;
	lifetime_earned: number;
	lifetime_spent: number;
	last_monthly_grant?: string;
	updated_at?: string;
}

export interface CreditTransaction {
	id: string;
	amount: number;
	balance_after: number;
	transaction_type: string;
	description: string;
	metadata?: unknown;
	reference_id?: string;
	created_at: string;
}

export interface CreditPackage {
	package_id: string;
	name: string;
	credits: number;
	bonus_percentage?: number;
	price_cents: number;
	currency: string;
	active: boolean;
	display_order: number;
	paddle_price_id?: string;
}

export interface ModelCost {
	[modelName: string]: number;
}

export interface TokenPricing {
	prompt_credits_per_1k: number;
	completion_credits_per_1k: number;
	description: string;
}

export interface ContextMultiplier {
	[contextSize: string]: number;
}

// API Response types
export interface CreditBalanceResponse {
	balance: number;
	lifetime_earned: number;
	lifetime_spent: number;
	last_monthly_grant?: string | null;
	updated_at: string;
}

export interface CreditTransactionsResponse {
	transactions: CreditTransaction[];
	total_count: number;
	has_more: boolean;
}

export interface CreditPackagesResponse {
	packages: CreditPackage[];
}

export interface ModelCostsResponse {
	model_costs: ModelCost;
	token_pricing: { [model: string]: TokenPricing };
	context_multipliers: ContextMultiplier;
}

export interface PurchaseCreditsRequest {
	package_id: string;
}

export interface PurchaseCreditsResponse {
	checkout_url: string;
	transaction_id: string;
}

export interface TransactionVerificationResponse {
	success: boolean;
	source?: 'database' | 'paddle';
	subscription?: {
		status: SubscriptionStatus;
	};
}

// Credit reservation for atomic operations
export interface CreditReservation {
	reservation_id: string;
	user_id: string;
	credits: number;
	expires_at: string;
}

// ============================================================================
// Subscription System Types
// ============================================================================

export type SubscriptionStatus =
	| 'active'
	| 'canceled'
	| 'past_due'
	| 'trialing'
	| 'unpaid'
	| 'incomplete'
	| 'expired'
	| 'pending_cancellation';

export interface Subscription {
	id: string;
	user_id: string;
	paddle_customer_id?: string;
	paddle_subscription_id?: string;
	plan_type: PlanType;
	status: SubscriptionStatus;
	current_period_start: string; // ISO date
	current_period_end: string; // ISO date
	cancel_at_period_end: boolean;
	trial_end?: string | null; // ISO date
	created_at: string; // ISO date
	updated_at: string; // ISO date
	credits_allocated_this_period?: boolean;
	soft_limit_override?: number | null;
}

export interface BillingFeatures {
	display_price: string;
	billing_period: 'monthly' | 'yearly';
	trial_days: number;
	cancel_anytime: boolean;
	monthly_equivalent?: string;
	savings_message?: string;
}

export interface PlanFeatures {
	plan_type: PlanType;
	display_name: string;
	description: string;
	price_monthly: number;
	price_yearly?: number;
	annual_savings_percent?: number;
	paddle_price_id_monthly?: string;
	paddle_price_id_yearly?: string;
	billing_features?: {
		monthly: BillingFeatures;
		yearly: BillingFeatures;
	};
	limits: {
		daily_messages: number;
		daily_limit_type: 'hard' | 'soft';
		context_tokens: number;
		chronicles_enabled: boolean;
		lorebooks_enabled: boolean;
		personas_enabled: boolean;
		max_characters: number;
		max_lorebooks: number;
	};
	credits: {
		included_monthly: number;
		welcome_bonus?: number;
		rollover_enabled?: boolean;
		rollover_max?: number;
		purchase_discount?: number;
	};
	models: {
		allowed: string[];
		default: string;
	};
	features: {
		priority_support?: boolean;
		api_access?: boolean;
		beta_features?: boolean;
		export_enabled?: boolean;
		import_enabled?: boolean;
		custom_personas?: boolean;
		priority_queue?: boolean;
		advanced_analytics?: boolean;
	};
}

// ============================================================================
// Usage Tracking Types
// ============================================================================

export interface DailyUsage {
	message_count: number;
	daily_limit: number;
	tier: string;
	usage_percentage: number;
	reset_time?: string;
	soft_limit_triggered?: boolean;
	throttle_delay_ms?: number;
}

export interface UsageStats {
	daily: DailyUsage;
	monthly: {
		messages_sent: number;
		tokens_consumed: number;
		credits_spent: number;
		period_start: string;
		period_end: string;
	};
	model_breakdown: {
		[model: string]: {
			message_count: number;
			token_count: number;
			credit_cost: number;
		};
	};
}

// ============================================================================
// Soft Limit Types
// ============================================================================

export interface SoftLimitThreshold {
	after_messages: number;
	delay_ms: number;
	fallback_model?: string;
	warning_message?: string;
}

export interface SoftLimitStatus {
	active: boolean;
	current_delay_ms: number;
	next_threshold?: SoftLimitThreshold;
	warning_message?: string;
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface SubscriptionResponse {
	subscription?: Subscription;
	plan_features?: PlanFeatures;
	usage?: DailyUsage;
	soft_limit_status?: SoftLimitStatus;
}

export interface PlansResponse {
	plans: PlanFeatures[];
	current_plan?: PlanType;
}

export interface CreateSubscriptionRequest {
	plan_type: PlanType;
	billing_period: 'monthly' | 'yearly';
}

export interface CreateSubscriptionResponse {
	checkout_url: string;
	subscription_id: string;
}

export interface OrderPreviewRequest {
	plan_type: PlanType;
	billing_period: 'monthly' | 'yearly';
}

export interface OrderLineItem {
	description: string;
	billing_period: string;
	amount: number;
	currency: string;
}

export interface OrderPreview {
	plan_name: string;
	plan_type: PlanType;
	billing_period: 'monthly' | 'yearly';
	line_items: OrderLineItem[];
	subtotal: number;
	tax_amount: number;
	total_amount: number;
	currency: string;
	next_billing_date: string;
	savings_message?: string;
	cancellation_policy: string;
}

export interface CancelSubscriptionRequest {
	immediate?: boolean;
	reason?: string;
}

export interface UsageResponse {
	daily: DailyUsage;
	monthly?: {
		messages_sent: number;
		tokens_consumed: number;
		credits_spent: number;
		period_start: string;
		period_end: string;
	};
	soft_limit_status?: SoftLimitStatus;
}

// ============================================================================
// Webhook Types
// ============================================================================

export interface PaddleWebhookEvent {
	event_type: string;
	data: {
		id: string;
		customer_id?: string;
		subscription_id?: string;
		transaction_id?: string;
		status?: string;
		items?: Array<{
			price_id: string;
			quantity: number;
		}>;
	};
	occurred_at: string;
}

// ============================================================================
// Combined User Type with Payment Info
// ============================================================================

export interface UserWithPaymentInfo {
	user_id: string;
	username: string;
	email: string;
	subscription?: Subscription;
	credit_balance?: CreditBalance;
	daily_usage?: DailyUsage;
}

// ============================================================================
// UI State Types
// ============================================================================

export interface PaymentUIState {
	isLoading: boolean;
	error: string | null;
	showPurchaseDialog: boolean;
	selectedPackage: CreditPackage | null;
	checkoutUrl: string | null;
	lastFetch: Date | null;
}

export interface CreditPurchaseFlow {
	step: 'select' | 'checkout' | 'processing' | 'success' | 'error';
	selectedPackage?: CreditPackage;
	transactionId?: string;
	errorMessage?: string;
}

// ============================================================================
// Model Selection with Credits
// ============================================================================

export interface ModelWithCost {
	id: string;
	name: string;
	description: string;
	creditCost: number;
	requiresSubscription: boolean;
	minimumTier?: PlanType;
	isAvailable: boolean;
	unavailableReason?: string;
}

// ============================================================================
// Error Types
// ============================================================================

export enum CreditError {
	InsufficientBalance = 'INSUFFICIENT_BALANCE',
	TransactionFailed = 'TRANSACTION_FAILED',
	InvalidPackage = 'INVALID_PACKAGE',
	DuplicateTransaction = 'DUPLICATE_TRANSACTION',
	UserNotFound = 'USER_NOT_FOUND',
	SubscriptionInactive = 'SUBSCRIPTION_INACTIVE',
	RateLimitExceeded = 'RATE_LIMIT_EXCEEDED'
}

export interface PaymentError {
	code: CreditError | string;
	message: string;
	details?: unknown;
}
