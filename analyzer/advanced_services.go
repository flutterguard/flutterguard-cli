package analyzer

import (
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// AdvancedServiceDetector detects various cloud platforms and third-party services
type AdvancedServiceDetector struct{}

func NewAdvancedServiceDetector() *AdvancedServiceDetector {
	return &AdvancedServiceDetector{}
}

// DetectAllServices scans content for all known services
func (asd *AdvancedServiceDetector) DetectAllServices(content string, domains []string) []models.ServiceUsage {
	var services []models.ServiceUsage
	contentLower := strings.ToLower(content)
	
	// AWS Detection
	if service := asd.detectAWS(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Google Cloud Platform
	if service := asd.detectGCP(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Microsoft Azure
	if service := asd.detectAzure(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Heroku
	if service := asd.detectHeroku(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// DigitalOcean
	if service := asd.detectDigitalOcean(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// MongoDB Atlas
	if service := asd.detectMongoDBAtlas(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// SendGrid
	if service := asd.detectSendGrid(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Twilio
	if service := asd.detectTwilio(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Algolia
	if service := asd.detectAlgolia(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Contentful
	if service := asd.detectContentful(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Cloudflare
	if service := asd.detectCloudflare(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Stripe (already exists but enhance it)
	if service := asd.detectStripe(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// PayPal
	if service := asd.detectPayPal(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Razorpay
	if service := asd.detectRazorpay(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// RevenueCat
	if service := asd.detectRevenueCat(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// OneSignal
	if service := asd.detectOneSignal(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Sentry
	if service := asd.detectSentry(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Amplitude
	if service := asd.detectAmplitude(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Mixpanel
	if service := asd.detectMixpanel(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// AppsFlyer
	if service := asd.detectAppsFlyer(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	// Branch.io
	if service := asd.detectBranch(contentLower, domains); service != nil {
		services = append(services, *service)
	}
	
	return services
}

func (asd *AdvancedServiceDetector) detectAWS(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"amazonaws.com", "aws.amazon.com", "s3.amazonaws",
		"aws_", "amazon_cognito", "aws-sdk",
		"dynamodb", "cognito", "lambda.aws", "elasticache",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Amazon Web Services (AWS)",
			Domains:    detectedDomains,
			Indicators: []string{"AWS cloud infrastructure detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectGCP(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"googleapis.com", "googleusercontent.com", "gcp",
		"google-cloud", "cloud.google", "gcloud",
		"google_cloud", "gcr.io",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Google Cloud Platform (GCP)",
			Domains:    detectedDomains,
			Indicators: []string{"GCP cloud services detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectAzure(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"azure.com", "windows.net", "azurewebsites",
		"azure-api", "servicebus.windows", "microsoft.azure",
		"azure_", "azuread",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Microsoft Azure",
			Domains:    detectedDomains,
			Indicators: []string{"Azure cloud services detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectHeroku(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"heroku.com", "herokuapp.com", "herokucdn.com",
		"heroku_", "heroku-",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Heroku",
			Domains:    detectedDomains,
			Indicators: []string{"Heroku platform detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectDigitalOcean(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"digitalocean.com", "digitaloceanspaces.com",
		"digitalocean_", "do_spaces",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "DigitalOcean",
			Domains:    detectedDomains,
			Indicators: []string{"DigitalOcean services detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectMongoDBAtlas(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"mongodb.net", "mongodb.com", "mongo_dart",
		"mongodb_", "mongodbatlas", "atlas.mongodb",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "MongoDB Atlas",
			Domains:    detectedDomains,
			Indicators: []string{"MongoDB database detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectSendGrid(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"sendgrid.com", "sendgrid.net", "sendgrid_",
		"sendgrid-api",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "SendGrid",
			Domains:    detectedDomains,
			Indicators: []string{"SendGrid email service detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectTwilio(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"twilio.com", "twilio_", "twilio-",
		"twiliocdn.com",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Twilio",
			Domains:    detectedDomains,
			Indicators: []string{"Twilio communication platform detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectAlgolia(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"algolia.net", "algolia.com", "algoliacdn.com",
		"algolia_", "algoliasearch",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Algolia",
			Domains:    detectedDomains,
			Indicators: []string{"Algolia search service detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectContentful(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"contentful.com", "ctfassets.net", "contentful_",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Contentful",
			Domains:    detectedDomains,
			Indicators: []string{"Contentful CMS detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectCloudflare(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"cloudflare.com", "cloudflaressl.com", "cf-",
		"cloudflare_", "cloudflare-",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Cloudflare",
			Domains:    detectedDomains,
			Indicators: []string{"Cloudflare CDN/security detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectStripe(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"stripe.com", "stripe.network", "stripe_",
		"stripejs", "pk_live", "pk_test",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Stripe",
			Domains:    detectedDomains,
			Indicators: []string{"Stripe payment processing detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectPayPal(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"paypal.com", "paypalobjects.com", "paypal_",
		"braintree", "paypal-sdk",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "PayPal",
			Domains:    detectedDomains,
			Indicators: []string{"PayPal payment service detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectRazorpay(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"razorpay.com", "razorpay_", "rzp_",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Razorpay",
			Domains:    detectedDomains,
			Indicators: []string{"Razorpay payment gateway detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectRevenueCat(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"revenuecat.com", "revenuecat_", "purchases_flutter",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "RevenueCat",
			Domains:    detectedDomains,
			Indicators: []string{"RevenueCat subscription management detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectOneSignal(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"onesignal.com", "onesignal_", "onesignal-",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "OneSignal",
			Domains:    detectedDomains,
			Indicators: []string{"OneSignal push notifications detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectSentry(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"sentry.io", "sentry_", "sentry-",
		"sentry_flutter",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Sentry",
			Domains:    detectedDomains,
			Indicators: []string{"Sentry error tracking detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectAmplitude(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"amplitude.com", "amplitude_", "amplitude-",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Amplitude",
			Domains:    detectedDomains,
			Indicators: []string{"Amplitude analytics detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectMixpanel(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"mixpanel.com", "mixpanel_", "mxpnl",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Mixpanel",
			Domains:    detectedDomains,
			Indicators: []string{"Mixpanel analytics detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectAppsFlyer(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"appsflyer.com", "appsflyer_", "onelink.me",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "AppsFlyer",
			Domains:    detectedDomains,
			Indicators: []string{"AppsFlyer attribution platform detected"},
		}
	}
	return nil
}

func (asd *AdvancedServiceDetector) detectBranch(content string, domains []string) *models.ServiceUsage {
	indicators := []string{
		"branch.io", "branch_", "app.link",
		"bnc.lt",
	}
	
	detectedDomains := filterDomainsByIndicators(domains, indicators)
	if len(detectedDomains) > 0 || containsAnyString(content, indicators) {
		return &models.ServiceUsage{
			Name:       "Branch.io",
			Domains:    detectedDomains,
			Indicators: []string{"Branch.io deep linking detected"},
		}
	}
	return nil
}

// Helper functions

func filterDomainsByIndicators(domains []string, indicators []string) []string {
	var matched []string
	for _, domain := range domains {
		domainLower := strings.ToLower(domain)
		for _, indicator := range indicators {
			if strings.Contains(domainLower, strings.ToLower(indicator)) {
				matched = append(matched, domain)
				break
			}
		}
	}
	return uniqueStringList(matched)
}

func containsAnyString(content string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(content, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func uniqueStringList(slice []string) []string {
	keys := make(map[string]bool)
	var unique []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			unique = append(unique, entry)
		}
	}
	return unique
}
