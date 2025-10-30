# Azure OpenAI Content Safety Validation Script

## Overview

The `Automated-ContentSafetyValidation.ps1` script provides comprehensive content safety validation for Azure OpenAI deployments across your Azure subscription. It validates Responsible AI (RAI) policies, content filters, and security configurations to ensure compliance with organizational security standards.

## Key Features

### 🔍 **Comprehensive Security Analysis**
- **Subscription-wide or Resource Group-specific scanning**
- **REST API-based validation** for accurate security assessment
- **Intelligent policy mode analysis** that distinguishes actual security risks from configuration preferences
- **Content filter validation** for all 8 core safety categories (Hate, Violence, Sexual, SelfHarm × 2 sources each)
- **Jailbreak protection detection**
- **Critical vs minor issue classification**

### 📊 **Enterprise Integration**
- **Automatic Log Analytics Workspace integration** with credential auto-retrieval
- **JSON report generation** for programmatic consumption
- **Data flattening** for easy querying in Log Analytics
- **Obsolete record management** to prevent data duplication

### 🛡️ **Advanced Security Insights**
- **Deployment type awareness** (Global Standard vs Data Zone Standard)
- **API version consistency** using latest Azure API (2024-10-01)
- **Microsoft default policy recognition** with assumed security compliance
- **Custom policy deep inspection** with detailed filter analysis

## Prerequisites

- **PowerShell 5.1 or later**
- **Azure CLI** installed and authenticated (`az login`)
- **Azure subscription access** with Reader permissions on Cognitive Services accounts
- **Log Analytics Workspace** (optional, for enterprise monitoring)

## Installation

1. Clone or download the script:
   ```powershell
   # Download the script to your local directory
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-repo/Automated-ContentSafetyValidation.ps1" -OutFile "Automated-ContentSafetyValidation.ps1"
   ```

2. Ensure Azure CLI is authenticated:
   ```powershell
   az login
   az account set --subscription "your-subscription-id"
   ```

## Usage Examples

### Basic Validation (Resource Group)
```powershell
.\Automated-ContentSafetyValidation.ps1 -ResourceGroupName "your-rg" -DetailedOutput
```

### Subscription-Wide Scan
```powershell
.\Automated-ContentSafetyValidation.ps1 -SubscriptionScope -DetailedOutput
```

### Enterprise Mode with Log Analytics
```powershell
.\Automated-ContentSafetyValidation.ps1 `
    -LogAnalyticsWorkspaceId "7f663309-e510-4d97-b822-4aafeecca16b" `
    -PurgeOldRecords `
    -DetailedOutput `
    -SubscriptionScope
```

### Automated Monitoring (without console output)
```powershell
.\Automated-ContentSafetyValidation.ps1 `
    -ResourceGroupName "production-rg" `
    -LogAnalyticsWorkspaceId "your-workspace-id" `
    -PurgeOldRecords
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ResourceGroupName` | String | No* | Target resource group name |
| `SubscriptionScope` | Switch | No* | Scan entire subscription |
| `LogAnalyticsWorkspaceId` | String | No | Log Analytics Workspace ID for data ingestion |
| `PurgeOldRecords` | Switch | No | Remove obsolete records before adding new ones |
| `DetailedOutput` | Switch | No | Show detailed console output during validation |

*Either `ResourceGroupName` or `SubscriptionScope` must be specified.

## Output Formats

### 1. Console Output
```
🔍 Azure OpenAI Content Safety Validation
📊 Scope: Subscription: 8cebb108-a4d5-402b-a0c4-f7556126277f
🔍 Found 15 Azure OpenAI accounts

🏢 Account: azure-openai-demo (rg-demo)
  📦 Deployment: gpt-4o
     Model: gpt-4o v2024-11-20
     RAI Policy: CustomContentFilter123
     Core Filters: 8/8 compliant
     ❌ CRITICAL: Jailbreak protection is disabled
     ❌ Status: Non-Compliant
```

### 2. JSON Report
```json
{
  "Summary": {
    "ValidationTimestamp": "2025-10-30 20:23:07",
    "Scope": "Subscription: 8cebb108-a4d5-402b-a0c4-f7556126277f",
    "TotalDeployments": 37,
    "CompliantCount": 32,
    "NonCompliantCount": 5,
    "UnknownCount": 0
  },
  "Details": [
    {
      "ResourceGroup": "rg-demo",
      "Account": "azure-openai-demo",
      "Deployment": "gpt-4o",
      "Model": "gpt-4o v2024-11-20",
      "RaiPolicy": "CustomContentFilter123",
      "ComplianceStatus": "Non-Compliant",
      "SecurityGaps": ["CRITICAL: Jailbreak protection is disabled"],
      "ContentFilters": [...],
      "Timestamp": "2025-10-30 20:22:58"
    }
  ]
}
```

### 3. Log Analytics Integration
Data is automatically sent to your Log Analytics Workspace in the `AzureOpenAIContentSafety_CL` table with flattened structure for easy querying.

## Understanding Results

### Compliance Status
- **✅ Compliant**: All security requirements met
- **❌ Non-Compliant**: Critical security gaps identified
- **❓ Unknown**: Unable to validate (rare)

### Security Gap Types
- **CRITICAL: No RAI policy assigned** - Deployment has no content safety protection
- **CRITICAL: Jailbreak protection is disabled** - Missing protection against prompt injection attacks
- **Filter-specific issues** - Individual content filters disabled or improperly configured

### Deployment Types
- **Global Standard**: Should automatically have Microsoft default policies
- **Data Zone Standard**: May legitimately have no auto-assigned policy due to data residency requirements

### Policy Types
- **Microsoft.Default / Microsoft.DefaultV2**: Microsoft-managed policies (assumed secure)
- **Custom policies**: Organization-specific policies (validated in detail)

## Troubleshooting

### Common Issues

1. **"No Azure OpenAI accounts found"**
   ```powershell
   # Verify Azure CLI authentication
   az account show
   
   # Check subscription context
   az account list --output table
   ```

2. **Log Analytics connection failed**
   ```powershell
   # Verify workspace ID
   az monitor log-analytics workspace show --workspace-name "your-workspace" --resource-group "your-rg"
   ```

3. **Permission denied errors**
   - Ensure you have Reader access to Cognitive Services accounts
   - Verify subscription-level access for `-SubscriptionScope`

### Debug Mode
For detailed troubleshooting, examine the JSON report:
```powershell
# Run validation and examine output
.\Automated-ContentSafetyValidation.ps1 -ResourceGroupName "your-rg" -DetailedOutput
Get-Content "ContentSafetyValidationReport.json" | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

## Advanced Configuration

### Custom Security Requirements
Modify the validation logic in the script to match your organization's security standards:

```powershell
# Example: Require stricter content filter thresholds
# Look for the validation section around line 400+ in the script
```

### Automated Scheduling
Use Task Scheduler or Azure Automation to run regular validations:

```powershell
# Example PowerShell scheduled task
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Automated-ContentSafetyValidation.ps1 -SubscriptionScope -LogAnalyticsWorkspaceId 'your-id'"
$Trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Azure OpenAI Security Validation"
```

## Log Analytics Queries

Once data is in Log Analytics, use these KQL queries for monitoring:

### Latest Validation Results
```kusto
// Get all data from the most recent validation run
let LatestTimestamp = ContentSafetyValidation001_CL
    | summarize max(TimeGenerated);

ContentSafetyValidation001_CL
| where TimeGenerated == toscalar(LatestTimestamp) and RecordType_s != 'OBSOLETE_MARKER' and ComplianceStatus_s == 'Non-Compliant' and RaiPolicy_s != '' 
| project TimeGenerated, Account_s, Deployment_s, ComplianceStatus_s, SecurityGaps_s, RaiPolicy_s
| order by Account_s, Deployment_s
```

### Latest Summary Dashboard
```kusto
// Summary statistics from the latest validation run
let LatestTimestamp = AzureOpenAIContentSafety_CL
| summarize max(TimeGenerated);

AzureOpenAIContentSafety_CL
| where TimeGenerated == toscalar(LatestTimestamp)
| summarize 
    LatestRun = max(TimeGenerated),
    TotalDeployments = count(),
    CompliantCount = countif(ComplianceStatus_s == "Compliant"),
    NonCompliantCount = countif(ComplianceStatus_s == "Non-Compliant"),
    CriticalIssues = countif(SecurityGaps_s contains "CRITICAL")
| extend ComplianceRate = round((CompliantCount * 100.0) / TotalDeployments, 1)
```

### Current Non-Compliant Deployments
```kusto
// Show only problematic deployments from the latest run
let LatestTimestamp = AzureOpenAIContentSafety_CL
| summarize max(TimeGenerated);

AzureOpenAIContentSafety_CL
| where TimeGenerated == toscalar(LatestTimestamp)
| where ComplianceStatus_s == "Non-Compliant"
| project 
    Account = Account_s,
    Deployment = Deployment_s,
    Model = Model_s,
    SecurityIssues = SecurityGaps_s,
    Policy = RaiPolicy_s
| order by Account, Deployment
```

### Compliance Overview (Historical)
```kusto
AzureOpenAIContentSafety_CL
| where TimeGenerated > ago(7d)
| summarize 
    Total = count(),
    Compliant = countif(ComplianceStatus_s == "Compliant"),
    NonCompliant = countif(ComplianceStatus_s == "Non-Compliant")
| extend ComplianceRate = round((Compliant * 100.0) / Total, 1)
```

### Security Gaps Trending
```kusto
AzureOpenAIContentSafety_CL
| where TimeGenerated > ago(30d) and ComplianceStatus_s == "Non-Compliant"
| extend SecurityGap = tostring(parse_json(SecurityGaps_s)[0])
| summarize count() by SecurityGap, bin(TimeGenerated, 1d)
| render timechart
```

### Critical Issues Alert
```kusto
AzureOpenAIContentSafety_CL
| where TimeGenerated > ago(1h)
| where SecurityGaps_s contains "CRITICAL"
| project TimeGenerated, Account_s, Deployment_s, SecurityGaps_s
```

## Security Best Practices

1. **Regular Validation**: Run weekly or after any deployment changes
2. **Monitor Trends**: Track compliance rates over time
3. **Alert on Critical Issues**: Set up Log Analytics alerts for security gaps
4. **Document Exceptions**: Maintain approved exceptions list for legitimate policy variations
5. **Review Data Zone Deployments**: Manually verify Data Zone Standard deployments have appropriate policies

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Azure OpenAI documentation for RAI policies
3. Examine the JSON output for detailed error information
4. Use Azure CLI debug mode: `az cognitiveservices --debug`

## Version History

- **v2.0**: Enhanced validation logic, intelligent policy mode analysis
- **v1.5**: Added Log Analytics integration, subscription scope support
- **v1.0**: Initial release with basic validation

---

**Note**: This script provides security validation but does not modify any Azure resources. All changes to RAI policies must be made manually through Azure Portal, CLI, or ARM templates.