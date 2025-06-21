# COVBudget 2.0 - Azure Deployment Ready

🚀 **Status: Infrastructure deployed! GitHub Actions will handle app deployment.**

A minimal Node.js web application configured for automatic deployment to Azure with database and key vault integration.

## Features

- **Web App**: Simple Express.js server
- **Database**: PostgreSQL integration with Azure Database for PostgreSQL
- **Key Vault**: Azure Key Vault for secure secrets management
- **CI/CD**: GitHub Actions workflow for automatic deployment
- **Infrastructure as Code**: Bicep templates for Azure resource provisioning

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitHub Repo   │───▶│  GitHub Actions │───▶│   Azure Web App │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Azure Key Vault │◀───│   Environment   │───▶│   PostgreSQL    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Azure subscription
- GitHub repository
- Azure CLI installed locally (for initial setup)

### 1. Local Development

1. Clone this repository
2. Copy `env.example` to `.env` and update values
3. Install dependencies:
   ```bash
   npm install
   ```
4. Run locally:
   ```bash
   npm start
   ```

### 2. Azure Setup

#### Create Azure Resources

Option A: Using Azure CLI and Bicep (Recommended)
```bash
# Login to Azure
az login

# Create resource group
az group create --name "rg-covbudget" --location "East US"

# Deploy infrastructure
az deployment group create \
  --resource-group "rg-covbudget" \
  --template-file infrastructure/main.bicep \
  --parameters infrastructure/parameters.json
```

Option B: Manual Setup through Azure Portal
1. Create a Resource Group
2. Create an App Service Plan (Linux, Node.js)
3. Create a Web App
4. Create a Key Vault
5. Create a PostgreSQL Flexible Server
6. Configure Web App to use System-Assigned Managed Identity
7. Grant Key Vault access to Web App identity

### 3. GitHub Secrets Configuration

Add these secrets to your GitHub repository (Settings → Secrets and variables → Actions):

#### Required Secrets:
- `AZURE_WEBAPP_NAME`: Your Azure Web App name
- `AZURE_WEBAPP_PUBLISH_PROFILE`: Download from Azure Portal → Your Web App → Get publish profile

#### Optional (for Infrastructure deployment):
- `AZURE_CREDENTIALS`: Service Principal JSON for Azure login
- `AZURE_SUBSCRIPTION_ID`: Your Azure subscription ID  
- `AZURE_RESOURCE_GROUP`: Your resource group name

#### Creating Azure Credentials:
```bash
az ad sp create-for-rbac --name "github-actions-covbudget" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{resource-group} \
  --sdk-auth
```

### 4. Deploy

1. Push to `main` or `master` branch
2. GitHub Actions will automatically:
   - Build the application
   - Deploy infrastructure (if configured)
   - Deploy the web app to Azure

## API Endpoints

- `GET /` - Application status and info
- `GET /health` - Health check with service status
- `GET /secrets/test` - Test Key Vault connection (development only)

## Environment Variables

### Production (Azure)
Set in Azure Web App Application Settings:
- `NODE_ENV=production`
- `AZURE_KEY_VAULT_URL=https://your-keyvault.vault.azure.net/`
- `DB_SECRET_NAME=database-connection-string`
- `TEST_SECRET_NAME=test-secret`

### Development (Local)
Set in `.env` file:
- `NODE_ENV=development`
- `PORT=3000`
- `DATABASE_URL=postgresql://user:pass@localhost:5432/db`

## Security Features

- **Managed Identity**: Web App uses System-Assigned Managed Identity
- **Key Vault Integration**: Secrets stored securely in Azure Key Vault
- **HTTPS Only**: Web App configured for HTTPS only
- **Database SSL**: PostgreSQL connections require SSL
- **Firewall Rules**: Database configured to allow Azure services only

## Monitoring

- Application logs available in Azure Portal → Web App → Log stream
- Health endpoint: `https://your-app.azurewebsites.net/health`
- Key Vault audit logs in Azure Monitor

## Cost Optimization

Current configuration uses minimal Azure resources:
- **App Service Plan**: B1 (Basic, ~$13/month)
- **PostgreSQL**: Burstable B1ms (~$12/month)  
- **Key Vault**: Standard tier (transactions-based)

## Customization

### Adding New Secrets
1. Add secret to Key Vault (Azure Portal or CLI)
2. Update application code to retrieve secret
3. Add environment variable for secret name

### Database Changes
1. Update `infrastructure/main.bicep` for different database configuration
2. Modify connection string in `server.js`
3. Update firewall rules as needed

### Scaling
- Modify `appServicePlanSkuName` in `infrastructure/parameters.json`
- Adjust PostgreSQL SKU in `infrastructure/main.bicep`

## Troubleshooting

### Deployment Issues
1. Check GitHub Actions logs
2. Verify Azure resource names match configuration
3. Ensure Managed Identity has Key Vault permissions

### Database Connection
1. Verify PostgreSQL firewall rules
2. Check connection string in Key Vault
3. Test database connectivity from Azure Cloud Shell

### Key Vault Access
1. Verify Web App Managed Identity is enabled
2. Check Key Vault access policies
3. Test secret retrieval via `/secrets/test` endpoint

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test locally
4. Create a pull request

## License

MIT License - feel free to use this template for your own projects. 