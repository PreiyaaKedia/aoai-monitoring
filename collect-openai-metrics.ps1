# Azure OpenAI Metrics Collection Script
# Creates a comprehensive table-based report of all OpenAI resources and their metrics

param(
    [string]$SubscriptionId = "8cebb108-a4d5-402b-a0c4-f7556126277f",
    [int]$DaysBack = 7
)

Write-Host "🔍 Azure OpenAI Metrics Collection Report" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Set subscription context
Write-Host "Setting subscription context..." -ForegroundColor Green
az account set --subscription $SubscriptionId

# Get all OpenAI resources
Write-Host "Discovering OpenAI resources..." -ForegroundColor Green
$resources = az graph query --graph-query "Resources | where type == 'microsoft.cognitiveservices/accounts' and kind == 'OpenAI' | where subscriptionId == '$SubscriptionId' | project name, resourceGroup, location, id" | ConvertFrom-Json

if ($resources.count -eq 0) {
    Write-Warning "No OpenAI resources found in subscription $SubscriptionId"
    exit 1
}

Write-Host "Found $($resources.data.Count) OpenAI resources" -ForegroundColor Green

# Calculate date range
$endTime = Get-Date
$startTime = $endTime.AddDays(-$DaysBack)
$startTimeStr = $startTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
$endTimeStr = $endTime.ToString("yyyy-MM-ddTHH:mm:ssZ")

# Date range for cost analysis (API expects YYYY-MM-DD format)
$costStartDate = $startTime.ToString("yyyy-MM-dd")
$costEndDate = $endTime.ToString("yyyy-MM-dd")

Write-Host "Collecting metrics from $startTimeStr to $endTimeStr" -ForegroundColor Yellow
Write-Host "Collecting cost data from $costStartDate to $costEndDate" -ForegroundColor Yellow

# Initialize results array
$results = @()

Write-Host "Processing resources in parallel..." -ForegroundColor Green

# Collect metrics for each resource in parallel
$results = $resources.data | ForEach-Object -Parallel {
    $resource = $_
    $SubscriptionId = $using:SubscriptionId
    $startTimeStr = $using:startTimeStr
    $endTimeStr = $using:endTimeStr
    $costStartDate = $using:costStartDate
    $costEndDate = $using:costEndDate
    
    $resourceId = $resource.id
    $resourceName = $resource.name
    $resourceGroup = $resource.resourceGroup
    $location = $resource.location
    
    Write-Host "  Processing: $resourceName" -ForegroundColor Gray
    
    try {
        # Collect all metrics in parallel using background jobs
        $jobs = @()
        
        # Create background jobs for each metric
        $jobs += Start-Job -ScriptBlock {
            param($resourceId, $startTimeStr, $endTimeStr)
            $data = az monitor metrics list --resource $resourceId --metric "TotalTokens" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
            return @{ metric = "TotalTokens"; value = ($data.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum }
        } -ArgumentList $resourceId, $startTimeStr, $endTimeStr
        
        $jobs += Start-Job -ScriptBlock {
            param($resourceId, $startTimeStr, $endTimeStr)
            $data = az monitor metrics list --resource $resourceId --metric "InputTokens" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
            return @{ metric = "InputTokens"; value = ($data.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum }
        } -ArgumentList $resourceId, $startTimeStr, $endTimeStr
        
        $jobs += Start-Job -ScriptBlock {
            param($resourceId, $startTimeStr, $endTimeStr)
            $data = az monitor metrics list --resource $resourceId --metric "OutputTokens" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
            return @{ metric = "OutputTokens"; value = ($data.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum }
        } -ArgumentList $resourceId, $startTimeStr, $endTimeStr
        
        $jobs += Start-Job -ScriptBlock {
            param($resourceId, $startTimeStr, $endTimeStr)
            $data = az monitor metrics list --resource $resourceId --metric "AzureOpenAIRequests" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
            return @{ metric = "AzureOpenAIRequests"; value = ($data.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum }
        } -ArgumentList $resourceId, $startTimeStr, $endTimeStr
        
        $jobs += Start-Job -ScriptBlock {
            param($resourceId, $startTimeStr, $endTimeStr)
            $data = az monitor metrics list --resource $resourceId --metric "SuccessfulCalls" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
            return @{ metric = "SuccessfulCalls"; value = ($data.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum }
        } -ArgumentList $resourceId, $startTimeStr, $endTimeStr
        
        $jobs += Start-Job -ScriptBlock {
            param($resourceId, $startTimeStr, $endTimeStr)
            $data = az monitor metrics list --resource $resourceId --metric "TotalErrors" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
            return @{ metric = "TotalErrors"; value = ($data.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum }
        } -ArgumentList $resourceId, $startTimeStr, $endTimeStr
        
        # Wait for all jobs to complete and collect results
        $metricsResults = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Extract metric values
        $totalTokens = ($metricsResults | Where-Object { $_.metric -eq "TotalTokens" }).value
        $inputTokens = ($metricsResults | Where-Object { $_.metric -eq "InputTokens" }).value
        $outputTokens = ($metricsResults | Where-Object { $_.metric -eq "OutputTokens" }).value
        $totalRequests = ($metricsResults | Where-Object { $_.metric -eq "AzureOpenAIRequests" }).value
        $successfulCalls = ($metricsResults | Where-Object { $_.metric -eq "SuccessfulCalls" }).value
        $totalErrors = ($metricsResults | Where-Object { $_.metric -eq "TotalErrors" }).value
        
        # Get cost data from Azure Cost Management
        try {
            # Use Azure REST API for cost management since az costmanagement might not be available
            $scope = "/subscriptions/$SubscriptionId"
            $body = @{
                type = "ActualCost"
                dataSet = @{
                    granularity = "Daily"
                    aggregation = @{
                        totalCost = @{
                            name = "Cost"
                            function = "Sum"
                        }
                    }
                    grouping = @(
                        @{
                            type = "Dimension"
                            name = "ResourceId"
                        }
                    )
                    filter = @{
                        dimensions = @{
                            name = "ResourceId"
                            operator = "In"
                            values = @($resourceId)
                        }
                    }
                }
                timeframe = "Custom"
                timePeriod = @{
                    from = $costStartDate
                    to = $costEndDate
                }
            } | ConvertTo-Json -Depth 10

            # Get access token
            $token = az account get-access-token --query accessToken --output tsv
            $headers = @{
                'Authorization' = "Bearer $token"
                'Content-Type' = 'application/json'
            }
            
            # Make REST API call to Cost Management
            $uri = "https://management.azure.com$scope/providers/Microsoft.CostManagement/query?api-version=2021-10-01"
            $response = Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers $headers
            
            $actualCost = if ($response.properties.rows.Count -gt 0) { 
                ($response.properties.rows | ForEach-Object { $_[0] } | Measure-Object -Sum).Sum 
            } else { 0 }
        } catch {
            Write-Warning "Error collecting cost data for $resourceName : $($_.Exception.Message)"
            $actualCost = 0
        }
        
    } catch {
        Write-Warning "Error collecting metrics for $resourceName : $($_.Exception.Message)"
        $totalTokens = 0
        $inputTokens = 0  
        $outputTokens = 0
        $totalRequests = 0
        $successfulCalls = 0
        $totalErrors = 0
        $actualCost = 0
    }
    
    # Return results object (for ForEach-Object -Parallel)
    return [PSCustomObject]@{
        ResourceName = $resourceName
        ResourceGroup = $resourceGroup
        Location = $location
        TotalTokens = [math]::Round($totalTokens, 0)
        InputTokens = [math]::Round($inputTokens, 0)
        OutputTokens = [math]::Round($outputTokens, 0)
        TotalRequests = [math]::Round($totalRequests, 0)
        SuccessfulCalls = [math]::Round($successfulCalls, 0)
        TotalErrors = [math]::Round($totalErrors, 0)
        SuccessRate = if ($totalRequests -gt 0) { [math]::Round(($successfulCalls / $totalRequests) * 100, 1) } else { 0 }
        ActualCostUSD = [math]::Round($actualCost, 2)
    }
} -ThrottleLimit 10

# Display results
Write-Host "`n📊 Azure OpenAI Metrics Summary (Last $DaysBack days)" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

$results | Format-Table -AutoSize

# Summary statistics
$totalTokensSum = ($results | Measure-Object -Property TotalTokens -Sum).Sum
$totalRequestsSum = ($results | Measure-Object -Property TotalRequests -Sum).Sum
$totalErrorsSum = ($results | Measure-Object -Property TotalErrors -Sum).Sum
$totalCostSum = ($results | Measure-Object -Property ActualCostUSD -Sum).Sum
$activeResources = ($results | Where-Object { $_.TotalTokens -gt 0 }).Count

Write-Host "`n📈 Overall Summary:" -ForegroundColor Yellow
Write-Host "Total Tokens Consumed: $totalTokensSum" -ForegroundColor White
Write-Host "Total Requests: $totalRequestsSum" -ForegroundColor White
Write-Host "Total Errors: $totalErrorsSum" -ForegroundColor White
Write-Host "Total Cost (USD): `$$totalCostSum" -ForegroundColor White
Write-Host "Active Resources (with usage): $activeResources / $($results.Count)" -ForegroundColor White

if ($totalRequestsSum -gt 0) {
    $overallSuccessRate = [math]::Round((($totalRequestsSum - $totalErrorsSum) / $totalRequestsSum) * 100, 1)
    Write-Host "Overall Success Rate: $overallSuccessRate%" -ForegroundColor White
}

# Export to CSV
$csvFile = "azure-openai-metrics-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$results | Export-Csv -Path $csvFile -NoTypeInformation
Write-Host "`n💾 Results exported to: $csvFile" -ForegroundColor Green

# Show resources with activity
$activeResourcesList = $results | Where-Object { $_.TotalTokens -gt 0 } | Sort-Object TotalTokens -Descending
if ($activeResourcesList.Count -gt 0) {
    Write-Host "`n🔥 Resources with Activity:" -ForegroundColor Green
    $activeResourcesList | Format-Table ResourceName, TotalTokens, TotalRequests, SuccessRate, ActualCostUSD -AutoSize
} else {
    Write-Host "`n⚠️  No resources show token usage in the last $DaysBack days." -ForegroundColor Yellow
    Write-Host "Consider extending the time range or checking if resources have been actively used." -ForegroundColor Yellow
}

Write-Host "`n✅ Metrics collection completed!" -ForegroundColor Green