/* Runtime configuration for the remediation console.
 *
 * This default file ships MOCK mode (no backend). At deploy time, EdgeStack
 * OVERWRITES this file in the UI bucket with the real API_BASE and Cognito
 * values, flipping the console to LIVE + authenticated mode.
 *
 * When API_BASE is empty, the UI runs fully client-side with sample data.
 */
window.APP_CONFIG = {
  API_BASE: "",            // e.g. "/api"  (CloudFront routes /api/* to the HTTP API)
  COGNITO: {
    domain: "",            // e.g. "vuln-remediation-dev-123456789012"
    region: "",            // e.g. "us-east-1"
    clientId: "",          // Cognito app client id
    redirectUri: "",       // e.g. "https://dxxxx.cloudfront.net/"
  },
};
