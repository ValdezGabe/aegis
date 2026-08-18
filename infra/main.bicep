@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Base name used to derive resource names.')
param appName string = 'aegis-gateway'

@description('Full image reference, e.g. myacr.azurecr.io/aegis-gateway:latest')
param containerImage string

@description('Container registry login server, e.g. myacr.azurecr.io')
param acrLoginServer string

@description('Container registry resource name (must already exist), e.g. myacr')
param acrName string

@description('Azure OpenAI endpoint, e.g. https://aegis-openai-01.openai.azure.com/openai/v1/')
param openAiEndpoint string

@description('Azure OpenAI deployment name, e.g. gpt-5-mini')
param openAiDeployment string

@description('Content Safety endpoint, e.g. https://aegis-contentsafety.cognitiveservices.azure.net/')
param contentSafetyEndpoint string

@secure()
@description('Azure OpenAI API key. Passed at deploy time; never stored in this file.')
param openAiKey string

@secure()
@description('Content Safety API key. Passed at deploy time; never stored in this file.')
param contentSafetyKey string

// Derived names (Key Vault names are globally unique and max 24 chars).
var keyVaultName = take('kv-${appName}-${uniqueString(resourceGroup().id)}', 24)
var logAnalyticsName = 'log-${appName}'
var environmentName = 'env-${appName}'
var identityName = 'id-${appName}'

// Built-in role definition IDs.
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'       // AcrPull

// --- Log Analytics workspace ---
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// --- User-assigned managed identity ---
// Created first, on purpose: it can be granted roles BEFORE the container app
// that uses it exists. A system-assigned identity doesn't exist until after the
// app is created, which would make the Key Vault reference fail on first deploy.
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
}

// --- Existing container registry (referenced, not created) ---
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

// --- Key Vault (RBAC authorization mode) ---
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: tenant().tenantId
    enableRbacAuthorization: true
  }
}

// --- Secrets written into the vault from secure parameters ---
resource openAiSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'openai-key'
  properties: { value: openAiKey }
}

resource contentSafetySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'contentsafety-key'
  properties: { value: contentSafetyKey }
}

// --- Grant the identity least-privilege read on the vault's secrets ---
resource kvRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identity.id, kvSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- Grant the identity pull access on the registry ---
resource acrRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, identity.id, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- Container Apps environment (wired to Log Analytics) ---
resource environment 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: environmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// --- Container App ---
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
      }
      registries: [
        {
          server: acrLoginServer
          identity: identity.id
        }
      ]
      secrets: [
        {
          name: 'openai-key'
          keyVaultUrl: '${keyVault.properties.vaultUri}secrets/openai-key'
          identity: identity.id
        }
        {
          name: 'contentsafety-key'
          keyVaultUrl: '${keyVault.properties.vaultUri}secrets/contentsafety-key'
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: appName
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'AZURE_OPENAI_ENDPOINT', value: openAiEndpoint }
            { name: 'AZURE_OPENAI_DEPLOYMENT', value: openAiDeployment }
            { name: 'CONTENT_SAFETY_ENDPOINT', value: contentSafetyEndpoint }
            { name: 'AZURE_OPENAI_KEY', secretRef: 'openai-key' }
            { name: 'CONTENT_SAFETY_KEY', secretRef: 'contentsafety-key' }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 3
      }
    }
  }
  // Ensure roles and secrets exist before the app tries to resolve them.
  dependsOn: [
    kvRoleAssignment
    acrRoleAssignment
    openAiSecret
    contentSafetySecret
  ]
}

output appUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
