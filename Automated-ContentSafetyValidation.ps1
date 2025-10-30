# Automated-ContentSafetyValidation.ps1
# Automated validation across all AI resources in a resource group using REST APIs

param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId = "8cebb108-a4d5-402b-a0c4-f7556126277f",
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$false)]
    [switch]$SubscriptionScope,
    
    [Parameter(Mandatory=$false)]
    [switch]$DetailedOutput,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ContentSafetyValidationReport.json",
    
    [Parameter(Mandatory=$false)]
    [string]$LogAnalyticsWorkspaceId,
    
    [Parameter(Mandatory=$false)]
    [string]$LogAnalyticsWorkspaceName,
    
    [Parameter(Mandatory=$false)]
    [string]$LogAnalyticsResourceGroup,
    
    [Parameter(Mandatory=$false)]
    [string]$LogAnalyticsSharedKey,
    
    [Parameter(Mandatory=$false)]
    [string]$LogType = "ContentSafetyValidation001",
    
    [Parameter(Mandatory=$false)]
    [switch]$PurgeOldRecords
)

Write-Host "=== Automated Content Safety Validation ===" -ForegroundColor Cyan

# Validate scope parameters
if ($SubscriptionScope -and $ResourceGroupName) {
    Write-Host "❌ Error: Cannot specify both -SubscriptionScope and -ResourceGroupName" -ForegroundColor Red
    Write-Host "Use -SubscriptionScope for entire subscription or -ResourceGroupName for specific resource group" -ForegroundColor Yellow
    return
}

if (-not $SubscriptionScope -and -not $ResourceGroupName) {
    Write-Host "❌ Error: Must specify either -SubscriptionScope or -ResourceGroupName" -ForegroundColor Red
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\Automated-ContentSafetyValidation.ps1 -SubscriptionScope" -ForegroundColor Gray
    Write-Host "  .\Automated-ContentSafetyValidation.ps1 -ResourceGroupName 'my-rg'" -ForegroundColor Gray
    return
}

# Set scope description
$scopeDescription = if ($SubscriptionScope) { 
    "entire subscription: $SubscriptionId" 
} else { 
    "resource group: $ResourceGroupName" 
}

Write-Host "Scanning all AI resources in $scopeDescription" -ForegroundColor Yellow

# Get access token for REST API calls
function Get-AzureAccessToken {
    try {
        $context = Get-AzContext
        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "https://management.azure.com/").AccessToken
        return $token
    } catch {
        Write-Host "Error getting access token: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to make REST API calls
function Invoke-AzureRestApi {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [string]$AccessToken
    )
    
    try {
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }
        
        $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers
        return $response
    } catch {
        Write-Host "REST API Error for $Uri : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to get Log Analytics Workspace information automatically
function Get-LogAnalyticsWorkspaceInfo {
    param(
        [string]$WorkspaceId,
        [string]$WorkspaceName,
        [string]$ResourceGroup,
        [string]$SubscriptionId
    )
    
    try {
        Write-Host "🔍 Retrieving Log Analytics Workspace information..." -ForegroundColor Cyan
        
        # If WorkspaceId is provided, find the workspace details
        if ($WorkspaceId -and -not $WorkspaceName) {
            Write-Host "   Looking up workspace by ID: $WorkspaceId" -ForegroundColor Gray
            $allWorkspaces = az monitor log-analytics workspace list --subscription $SubscriptionId --query "[?customerId=='$WorkspaceId']" | ConvertFrom-Json
            if ($allWorkspaces -and $allWorkspaces.Count -gt 0) {
                $workspace = $allWorkspaces[0]
                $WorkspaceName = $workspace.name
                $ResourceGroup = $workspace.resourceGroup
                Write-Host "   ✅ Found workspace: $WorkspaceName in RG: $ResourceGroup" -ForegroundColor Green
            } else {
                Write-Host "   ❌ Workspace with ID $WorkspaceId not found" -ForegroundColor Red
                return $null
            }
        }
        
        # Get shared keys
        Write-Host "   Retrieving shared keys..." -ForegroundColor Gray
        $keysJson = az monitor log-analytics workspace get-shared-keys --resource-group $ResourceGroup --workspace-name $WorkspaceName --subscription $SubscriptionId
        
        if ($LASTEXITCODE -eq 0) {
            $keys = $keysJson | ConvertFrom-Json
            Write-Host "   ✅ Successfully retrieved workspace keys" -ForegroundColor Green
            
            return @{
                WorkspaceId = $WorkspaceId
                WorkspaceName = $WorkspaceName
                ResourceGroup = $ResourceGroup
                PrimaryKey = $keys.primarySharedKey
                SecondaryKey = $keys.secondarySharedKey
            }
        } else {
            Write-Host "   ❌ Failed to retrieve workspace keys: $keysJson" -ForegroundColor Red
            return $null
        }
        
    } catch {
        Write-Host "   ❌ Error retrieving workspace info: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to purge old records from Log Analytics
function Remove-OldLogAnalyticsRecords {
    param(
        [string]$WorkspaceId,
        [string]$LogType,
        [string]$ResourceGroup,
        [string]$SharedKey
    )
    
    try {
        Write-Host "🗑️ Marking old records as obsolete for ResourceGroup: $ResourceGroup..." -ForegroundColor Yellow
        
        # Create obsolete marker records to indicate previous data is invalid
        $obsoleteRecord = @{
            TimeGenerated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ResourceGroup = $ResourceGroup
            Account = "OBSOLETE_MARKER"
            Deployment = "PREVIOUS_RECORDS_MARKED_OBSOLETE"
            Model = "N/A"
            RaiPolicy = "N/A"
            ComplianceStatus = "OBSOLETE"
            SecurityGapCount = 0
            SecurityGaps = "Previous records marked obsolete - use latest ValidationRun only"
            ContentFilterCount = 0
            ContentFilters = "OBSOLETE"
            HasBlockingFilters = $false
            HasEnabledFilters = $false
            ValidationRun = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
            RecordType = "OBSOLETE_MARKER"
        }
        
        # Send obsolete marker
        $success = Send-LogAnalyticsData -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogData @($obsoleteRecord) -LogType $LogType
        
        if ($success) {
            Write-Host "   ✅ Obsolete marker sent successfully" -ForegroundColor Green
            Write-Host "   💡 Filter old records with: | where RecordType_s != 'OBSOLETE_MARKER'" -ForegroundColor Gray
            Write-Host "   💡 Or use latest ValidationRun: | where ValidationRun_s == 'latest-run-id'" -ForegroundColor Gray
        }
        
        return $success
        
    } catch {
        Write-Host "   ❌ Error during purge operation: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
function Send-LogAnalyticsData {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WorkspaceId,
        
        [Parameter(Mandatory=$true)]
        [string]$SharedKey,
        
        [Parameter(Mandatory=$true)]
        [object]$LogData,
        
        [Parameter(Mandatory=$true)]
        [string]$LogType
    )
    
    try {
        # Convert data to JSON
        $jsonData = $LogData | ConvertTo-Json -Depth 10
        $body = [System.Text.Encoding]::UTF8.GetBytes($jsonData)
        
        # Generate authorization signature
        $date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length
        $stringToHash = "POST`n$contentLength`napplication/json`nx-ms-date:$date`n/api/logs"
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = "SharedKey {0}:{1}" -f $WorkspaceId, $encodedHash
        
        # Build URI
        $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        
        # Create headers
        $headers = @{
            "Authorization" = $authorization
            "Log-Type" = $LogType
            "x-ms-date" = $date
            "time-generated-field" = "Timestamp"
        }
        
        # Send data
        $response = Invoke-RestMethod -Uri $uri -Method "POST" -Body $body -Headers $headers -ContentType "application/json"
        Write-Host "✅ Data successfully sent to Log Analytics Workspace" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "❌ Error sending data to Log Analytics: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Get access token
$accessToken = Get-AzureAccessToken
if (-not $accessToken) {
    Write-Host "Failed to get access token. Exiting." -ForegroundColor Red
    return
}

# Find all Cognitive Services accounts
Write-Host "`n🔍 Discovering AI resources..." -ForegroundColor Cyan

# Build the appropriate URI based on scope
if ($SubscriptionScope) {
    $resourcesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resources?`$filter=resourceType eq 'Microsoft.CognitiveServices/accounts'&api-version=2021-04-01"
} else {
    $resourcesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/resources?api-version=2021-04-01"
}

Write-Host "   Query URI: $resourcesUri" -ForegroundColor Gray
$resources = Invoke-AzureRestApi -Uri $resourcesUri -AccessToken $accessToken

if ($SubscriptionScope) {
    $aiAccounts = $resources.value | Where-Object { $_.type -eq "Microsoft.CognitiveServices/accounts" }
} else {
    $aiAccounts = $resources.value | Where-Object { $_.type -eq "Microsoft.CognitiveServices/accounts" }
}

if (-not $aiAccounts) {
    $scopeMsg = if ($SubscriptionScope) { "subscription" } else { "resource group" }
    Write-Host "No AI/Cognitive Services accounts found in $scopeMsg." -ForegroundColor Yellow
    return
}

Write-Host "   Found $($aiAccounts.Count) AI/Cognitive Services account(s)" -ForegroundColor Green

$validationResults = @()

foreach ($account in $aiAccounts) {
    $accountName = $account.name
    
    # Extract resource group from account resource ID for subscription scope
    if ($SubscriptionScope) {
        $accountResourceGroup = $account.id.Split('/')[4]  # Extract RG from resource ID
    } else {
        $accountResourceGroup = $ResourceGroupName
    }
    
    Write-Host "`n=== AI Account: $accountName (RG: $accountResourceGroup) ===" -ForegroundColor White
    
    # Get deployments for this account
    $deploymentsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$accountResourceGroup/providers/Microsoft.CognitiveServices/accounts/$accountName/deployments?api-version=2024-10-01"
    $deployments = Invoke-AzureRestApi -Uri $deploymentsUri -AccessToken $accessToken
    
    if (-not $deployments -or -not $deployments.value) {
        Write-Host "  No deployments found" -ForegroundColor Gray
        continue
    }
    
    foreach ($deployment in $deployments.value) {
        $deploymentName = $deployment.name
        $raiPolicyName = $deployment.properties.raiPolicyName
        
        Write-Host "`n  📦 Deployment: $deploymentName" -ForegroundColor Cyan
        Write-Host "     Model: $($deployment.properties.model.name) v$($deployment.properties.model.version)"
        Write-Host "     RAI Policy: $raiPolicyName"
        
        $deploymentResult = @{
            ResourceGroup = $accountResourceGroup
            Account = $accountName
            Deployment = $deploymentName
            Model = "$($deployment.properties.model.name) v$($deployment.properties.model.version)"
            RaiPolicy = $raiPolicyName
            ComplianceStatus = "Unknown"
            SecurityGaps = @()
            ContentFilters = @()
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Validate RAI policy assignment
        if (-not $raiPolicyName -or $raiPolicyName -eq "") {
            Write-Host "     ❌ CRITICAL: No RAI policy assigned" -ForegroundColor Red
            $deploymentResult.ComplianceStatus = "Non-Compliant"
            $deploymentResult.SecurityGaps += "No RAI policy assigned"
            $validationResults += $deploymentResult
            continue
        }
        
        # Handle Microsoft default policies
        if ($raiPolicyName -like "Microsoft.*") {
            Write-Host "     ✅ Microsoft Default Policy - Assumed secure" -ForegroundColor Green
            $deploymentResult.ComplianceStatus = "Compliant"
            $deploymentResult.ContentFilters += @{
                Type = "Microsoft Default"
                Status = "Assumed secure"
                Details = "Cannot inspect Microsoft default policies"
            }
            $validationResults += $deploymentResult
            continue
        }
        
        # Validate custom RAI policies using multiple approaches
        Write-Host "     🔍 Validating custom RAI policy..." -ForegroundColor Yellow
        
        # Approach 1: Direct REST API call
        $raiPolicyUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$accountResourceGroup/providers/Microsoft.CognitiveServices/accounts/$accountName/raiPolicies/$raiPolicyName" + "?api-version=2024-10-01"
        $raiPolicy = Invoke-AzureRestApi -Uri $raiPolicyUri -AccessToken $accessToken
        
        if ($raiPolicy) {
            Write-Host "     📋 Policy retrieved via REST API" -ForegroundColor Green
            
            # Analyze the policy configuration
            $securityGaps = @()
            $isCompliant = $true
            
            # Enhanced policy mode analysis - focus on actual security enforcement
            $policyMode = $raiPolicy.properties.mode
            Write-Host "     Policy Mode: $policyMode" -ForegroundColor Gray
            
            # Note: "Default" mode can still be secure if filters are properly configured
            # Only flag mode as an issue if it's explicitly "Off" or missing
            if (-not $policyMode -or $policyMode -eq "Off") {
                $securityGaps += "Policy mode is disabled or missing"
                $isCompliant = $false
            } elseif ($policyMode -eq "Default") {
                Write-Host "     💡 Policy uses 'Default' mode - checking individual filter enforcement" -ForegroundColor Yellow
            }
            
            # Enhanced content filter validation
            $requiredFilters = @("Hate", "Violence", "Sexual", "SelfHarm")  # Note: "SelfHarm" matches API "Selfharm"
            $requiredSources = @("Prompt", "Completion")
            
            $contentFilters = $raiPolicy.properties.contentFilters
            $compliantFilters = 0
            $totalRequiredFilters = $requiredFilters.Count * $requiredSources.Count
            
            if ($contentFilters) {
                Write-Host "     🛡️ Analyzing content filters..." -ForegroundColor Gray
                
                foreach ($filterName in $requiredFilters) {
                    foreach ($source in $requiredSources) {
                        # Handle API inconsistency: "SelfHarm" in requirement vs "Selfharm" in API
                        $apiFilterName = if ($filterName -eq "SelfHarm") { "Selfharm" } else { $filterName }
                        $filter = $contentFilters | Where-Object { $_.name -eq $apiFilterName -and $_.source -eq $source }
                        
                        if (-not $filter) {
                            $securityGaps += "Missing $filterName filter for $source"
                            $isCompliant = $false
                        } elseif (-not $filter.enabled) {
                            $securityGaps += "$filterName filter for $source is disabled"
                            $isCompliant = $false
                        } elseif (-not $filter.blocking) {
                            $securityGaps += "$filterName filter for $source is not blocking (set to annotate-only)"
                            $isCompliant = $false
                        } else {
                            # Filter is compliant
                            $compliantFilters++
                            $deploymentResult.ContentFilters += @{
                                Name = $filterName
                                Source = $source
                                Status = "Compliant"
                                Enabled = $filter.enabled
                                Blocking = $filter.blocking
                                Severity = $filter.severityThreshold
                            }
                        }
                    }
                }
                
                Write-Host "     📊 Core Filters: $compliantFilters/$totalRequiredFilters compliant" -ForegroundColor $(if ($compliantFilters -eq $totalRequiredFilters) { "Green" } else { "Yellow" })
                
                # Check critical prompt shields (Jailbreak Protection)
                Write-Host "     🔒 Checking prompt shields..." -ForegroundColor Gray
                $jailbreakFilter = $contentFilters | Where-Object { $_.name -eq "Jailbreak" -and $_.source -eq "Prompt" }
                
                if (-not $jailbreakFilter) {
                    $securityGaps += "CRITICAL: Missing Jailbreak (Prompt Shield) protection"
                    $isCompliant = $false
                    Write-Host "       ❌ Jailbreak protection: Not configured" -ForegroundColor Red
                } elseif (-not $jailbreakFilter.enabled) {
                    $securityGaps += "CRITICAL: Jailbreak protection is disabled"
                    $isCompliant = $false
                    Write-Host "       ❌ Jailbreak protection: Disabled" -ForegroundColor Red
                } elseif (-not $jailbreakFilter.blocking) {
                    $securityGaps += "CRITICAL: Jailbreak protection is not blocking (monitoring only)"
                    $isCompliant = $false
                    Write-Host "       ⚠️ Jailbreak protection: Monitoring only (not blocking)" -ForegroundColor Yellow
                } else {
                    Write-Host "       ✅ Jailbreak protection: Enabled and blocking" -ForegroundColor Green
                    $deploymentResult.ContentFilters += @{
                        Name = "Jailbreak"
                        Source = "Prompt"
                        Status = "Compliant"
                        Enabled = $jailbreakFilter.enabled
                        Blocking = $jailbreakFilter.blocking
                    }
                }
            } else {
                $securityGaps += "No content filters configured"
                $isCompliant = $false
            }
            
            # Enhanced compliance assessment
            $criticalGaps = $securityGaps | Where-Object { $_ -like "*CRITICAL*" }
            $minorGaps = $securityGaps | Where-Object { $_ -notlike "*CRITICAL*" }
            
            if ($isCompliant) {
                $deploymentResult.ComplianceStatus = "Compliant"
                Write-Host "     ✅ COMPLIANT: All security controls properly configured" -ForegroundColor Green
                Write-Host "       Policy Mode: $policyMode | Core Filters: $compliantFilters/$totalRequiredFilters | Jailbreak: Protected" -ForegroundColor Gray
            } elseif ($criticalGaps.Count -gt 0) {
                $deploymentResult.ComplianceStatus = "Non-Compliant"
                Write-Host "     ❌ NON-COMPLIANT: Critical security gaps detected" -ForegroundColor Red
                foreach ($gap in $criticalGaps) {
                    Write-Host "       • $gap" -ForegroundColor Red
                }
                if ($minorGaps.Count -gt 0) {
                    Write-Host "     Additional issues:" -ForegroundColor Yellow
                    foreach ($gap in $minorGaps) {
                        Write-Host "       • $gap" -ForegroundColor Yellow
                    }
                }
            } else {
                $deploymentResult.ComplianceStatus = "Non-Compliant"
                Write-Host "     ⚠️ NON-COMPLIANT: Configuration issues detected" -ForegroundColor Yellow
                foreach ($gap in $minorGaps) {
                    Write-Host "       • $gap" -ForegroundColor Yellow
                }
            }
            
            $deploymentResult.SecurityGaps = $securityGaps
            
        } else {
            Write-Host "     ⚠️  Could not retrieve policy details via REST API" -ForegroundColor Yellow
            $deploymentResult.ComplianceStatus = "Unknown"
            $deploymentResult.SecurityGaps += "Cannot retrieve policy configuration"
        }
        
        $validationResults += $deploymentResult
    }
}

# Generate summary report
Write-Host "`n📊 === VALIDATION SUMMARY ===" -ForegroundColor Magenta
$compliantCount = ($validationResults | Where-Object { $_.ComplianceStatus -eq "Compliant" }).Count
$nonCompliantCount = ($validationResults | Where-Object { $_.ComplianceStatus -eq "Non-Compliant" }).Count
$unknownCount = ($validationResults | Where-Object { $_.ComplianceStatus -eq "Unknown" }).Count

Write-Host "Total Deployments: $($validationResults.Count)" -ForegroundColor White
Write-Host "✅ Compliant: $compliantCount" -ForegroundColor Green
Write-Host "❌ Non-Compliant: $nonCompliantCount" -ForegroundColor Red
Write-Host "⚠️  Unknown: $unknownCount" -ForegroundColor Yellow

# Show critical security gaps
$criticalGaps = $validationResults | Where-Object { $_.SecurityGaps.Count -gt 0 }
if ($criticalGaps) {
    Write-Host "`n🚨 CRITICAL SECURITY GAPS:" -ForegroundColor Red
    foreach ($deployment in $criticalGaps) {
        Write-Host "  $($deployment.Account)/$($deployment.Deployment):" -ForegroundColor White
        foreach ($gap in $deployment.SecurityGaps) {
            Write-Host "    • $gap" -ForegroundColor Red
        }
    }
}

# Export detailed report
$report = @{
    Summary = @{
        Scope = if ($SubscriptionScope) { "Subscription: $SubscriptionId" } else { "ResourceGroup: $ResourceGroupName" }
        ResourceGroup = if ($SubscriptionScope) { "ALL" } else { $ResourceGroupName }
        TotalDeployments = $validationResults.Count
        CompliantCount = $compliantCount
        NonCompliantCount = $nonCompliantCount
        UnknownCount = $unknownCount
        ValidationTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    Details = $validationResults
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n📄 Detailed report saved to: $OutputPath" -ForegroundColor Green

# Send data to Log Analytics Workspace if configured
if ($LogAnalyticsWorkspaceId -or ($LogAnalyticsWorkspaceName -and $LogAnalyticsResourceGroup)) {
    Write-Host "`n📊 Configuring Log Analytics integration..." -ForegroundColor Cyan
    
    # Auto-retrieve workspace information if not provided
    $workspaceInfo = $null
    
    if (-not $LogAnalyticsSharedKey) {
        if ($LogAnalyticsWorkspaceId) {
            $workspaceInfo = Get-LogAnalyticsWorkspaceInfo -WorkspaceId $LogAnalyticsWorkspaceId -SubscriptionId $SubscriptionId
        } elseif ($LogAnalyticsWorkspaceName -and $LogAnalyticsResourceGroup) {
            # Get workspace ID first
            Write-Host "   Getting workspace ID for: $LogAnalyticsWorkspaceName" -ForegroundColor Gray
            $workspaceJson = az monitor log-analytics workspace show --resource-group $LogAnalyticsResourceGroup --workspace-name $LogAnalyticsWorkspaceName --subscription $SubscriptionId
            if ($LASTEXITCODE -eq 0) {
                $workspace = $workspaceJson | ConvertFrom-Json
                $LogAnalyticsWorkspaceId = $workspace.customerId
                $workspaceInfo = Get-LogAnalyticsWorkspaceInfo -WorkspaceId $LogAnalyticsWorkspaceId -WorkspaceName $LogAnalyticsWorkspaceName -ResourceGroup $LogAnalyticsResourceGroup -SubscriptionId $SubscriptionId
            }
        }
        
        if ($workspaceInfo) {
            $LogAnalyticsSharedKey = $workspaceInfo.PrimaryKey
            $LogAnalyticsWorkspaceId = $workspaceInfo.WorkspaceId
            Write-Host "   ✅ Automatically retrieved workspace credentials" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Failed to retrieve workspace credentials automatically" -ForegroundColor Red
        }
    }
    
    if ($LogAnalyticsWorkspaceId -and $LogAnalyticsSharedKey) {
        # Purge old records if requested
        if ($PurgeOldRecords) {
            $scopeForPurge = if ($SubscriptionScope) { "SUBSCRIPTION:$SubscriptionId" } else { $ResourceGroupName }
            Remove-OldLogAnalyticsRecords -WorkspaceId $LogAnalyticsWorkspaceId -LogType $LogType -ResourceGroup $scopeForPurge -SharedKey $LogAnalyticsSharedKey
        }
        
        Write-Host "`n📊 Sending data to Log Analytics Workspace..." -ForegroundColor Cyan
        
        # Prepare individual records for Log Analytics (one record per deployment)
        $logRecords = @()
        $validationRunId = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        
        foreach ($deployment in $validationResults) {
            $record = @{
                TimeGenerated = $deployment.Timestamp
                Scope = if ($SubscriptionScope) { "Subscription" } else { "ResourceGroup" }
                ResourceGroup = $deployment.ResourceGroup
                Account = $deployment.Account
                Deployment = $deployment.Deployment
                Model = $deployment.Model
                RaiPolicy = $deployment.RaiPolicy
                ComplianceStatus = $deployment.ComplianceStatus
                SecurityGapCount = $deployment.SecurityGaps.Count
                SecurityGaps = ($deployment.SecurityGaps -join "; ")
                ContentFilterCount = $deployment.ContentFilters.Count
                ValidationRun = $validationRunId
                RecordType = "VALIDATION_DATA"
            }
            
            # Flatten content filters into single record fields
            $contentFilterSummary = @()
            $hasBlockingFilters = $false
            $hasEnabledFilters = $false
            
            if ($deployment.ContentFilters.Count -gt 0) {
                foreach ($filter in $deployment.ContentFilters) {
                    if ($filter.Name -and $filter.Source) {
                        $filterSummary = "$($filter.Name)($($filter.Source))"
                        if ($filter.Enabled) {
                            $filterSummary += ":Enabled"
                            $hasEnabledFilters = $true
                        } else {
                            $filterSummary += ":Disabled"
                        }
                        if ($filter.Blocking) {
                            $filterSummary += ":Blocking"
                            $hasBlockingFilters = $true
                        } else {
                            $filterSummary += ":NonBlocking"
                        }
                        $contentFilterSummary += $filterSummary
                    } elseif ($filter.Type) {
                        $contentFilterSummary += $filter.Type
                    }
                }
                
                $record["ContentFilters"] = ($contentFilterSummary -join ", ")
                $record["HasBlockingFilters"] = $hasBlockingFilters
                $record["HasEnabledFilters"] = $hasEnabledFilters
            } else {
                $record["ContentFilters"] = "None"
                $record["HasBlockingFilters"] = $false
                $record["HasEnabledFilters"] = $false
            }
            
            $logRecords += $record
        }
        
        # Send data to Log Analytics
        $logAnalyticsSuccess = Send-LogAnalyticsData -WorkspaceId $LogAnalyticsWorkspaceId -SharedKey $LogAnalyticsSharedKey -LogData $logRecords -LogType $LogType
        
        if ($logAnalyticsSuccess) {
            Write-Host "📈 Log Analytics Details:" -ForegroundColor Green
            Write-Host "   Workspace ID: $LogAnalyticsWorkspaceId" -ForegroundColor White
            Write-Host "   Log Type: $LogType" -ForegroundColor White
            Write-Host "   Records Sent: $($logRecords.Count)" -ForegroundColor White
            Write-Host "   Validation Run ID: $validationRunId" -ForegroundColor White
            Write-Host "`n📋 Recommended Queries:" -ForegroundColor Yellow
            Write-Host "   // Latest validation only" -ForegroundColor Gray
            Write-Host "   $LogType" + "_CL | where ValidationRun_s == '$validationRunId'" -ForegroundColor Cyan
            Write-Host "`n   // Active records (exclude obsolete)" -ForegroundColor Gray  
            Write-Host "   $LogType" + "_CL | where RecordType_s == 'VALIDATION_DATA' | where TimeGenerated > ago(1h)" -ForegroundColor Cyan
            
            if ($SubscriptionScope) {
                Write-Host "`n   // Subscription-wide summary" -ForegroundColor Gray
                Write-Host "   $LogType" + "_CL | where Scope_s == 'Subscription' and RecordType_s == 'VALIDATION_DATA'" -ForegroundColor Cyan
                Write-Host "   | summarize arg_max(TimeGenerated, *) by ResourceGroup_s, Account_s, Deployment_s" -ForegroundColor Cyan
                Write-Host "`n   // By Resource Group" -ForegroundColor Gray
                Write-Host "   $LogType" + "_CL | where Scope_s == 'Subscription' and RecordType_s == 'VALIDATION_DATA'" -ForegroundColor Cyan
                Write-Host "   | summarize count() by ResourceGroup_s, ComplianceStatus_s" -ForegroundColor Cyan
            } else {
                Write-Host "`n   // Latest by ResourceGroup" -ForegroundColor Gray
                Write-Host "   $LogType" + "_CL | where ResourceGroup_s == '$ResourceGroupName' and RecordType_s == 'VALIDATION_DATA'" -ForegroundColor Cyan
                Write-Host "   | summarize arg_max(TimeGenerated, *) by Account_s, Deployment_s" -ForegroundColor Cyan
            }
        }
    } else {
        Write-Host "❌ Log Analytics integration failed - missing credentials" -ForegroundColor Red
    }
} else {
    Write-Host "`n💡 To enable Log Analytics integration, provide one of:" -ForegroundColor Yellow
    Write-Host "   -LogAnalyticsWorkspaceId <workspace-id>" -ForegroundColor Gray
    Write-Host "   -LogAnalyticsWorkspaceName <name> -LogAnalyticsResourceGroup <rg>" -ForegroundColor Gray
    Write-Host "   (Shared keys will be retrieved automatically)" -ForegroundColor Gray
}

Write-Host "`n=== Automated validation complete ===" -ForegroundColor Cyan