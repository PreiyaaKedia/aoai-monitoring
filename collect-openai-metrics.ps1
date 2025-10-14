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

Write-Host "Collecting metrics from $startTimeStr to $endTimeStr" -ForegroundColor Yellow

# Initialize results array
$results = @()

# Collect metrics for each resource
foreach ($resource in $resources.data) {
    Write-Host "Processing: $($resource.name)" -ForegroundColor White
    
    $resourceId = $resource.id
    $resourceName = $resource.name
    $resourceGroup = $resource.resourceGroup
    $location = $resource.location
    
    try {
        # Get TotalTokens
        $totalTokensData = az monitor metrics list --resource $resourceId --metric "TotalTokens" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
        $totalTokens = ($totalTokensData.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum
        
        # Get InputTokens  
        $inputTokensData = az monitor metrics list --resource $resourceId --metric "InputTokens" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
        $inputTokens = ($inputTokensData.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum
        
        # Get OutputTokens
        $outputTokensData = az monitor metrics list --resource $resourceId --metric "OutputTokens" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
        $outputTokens = ($outputTokensData.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum
        
        # Get Requests
        $requestsData = az monitor metrics list --resource $resourceId --metric "AzureOpenAIRequests" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
        $totalRequests = ($requestsData.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum
        
        # Get Successful Calls
        $successData = az monitor metrics list --resource $resourceId --metric "SuccessfulCalls" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
        $successfulCalls = ($successData.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum
        
        # Get Errors
        $errorData = az monitor metrics list --resource $resourceId --metric "TotalErrors" --start-time $startTimeStr --end-time $endTimeStr --interval PT1H --aggregation Total --output json | ConvertFrom-Json
        $totalErrors = ($errorData.value[0].timeseries[0].data | Measure-Object -Property total -Sum).Sum
        
    } catch {
        Write-Warning "Error collecting metrics for $resourceName : $($_.Exception.Message)"
        $totalTokens = 0
        $inputTokens = 0  
        $outputTokens = 0
        $totalRequests = 0
        $successfulCalls = 0
        $totalErrors = 0
    }
    
    # Add to results
    $results += [PSCustomObject]@{
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
    }
}

# Display results
Write-Host "`n📊 Azure OpenAI Metrics Summary (Last $DaysBack days)" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

$results | Format-Table -AutoSize

# Summary statistics
$totalTokensSum = ($results | Measure-Object -Property TotalTokens -Sum).Sum
$totalRequestsSum = ($results | Measure-Object -Property TotalRequests -Sum).Sum
$totalErrorsSum = ($results | Measure-Object -Property TotalErrors -Sum).Sum
$activeResources = ($results | Where-Object { $_.TotalTokens -gt 0 }).Count

Write-Host "`n📈 Overall Summary:" -ForegroundColor Yellow
Write-Host "Total Tokens Consumed: $totalTokensSum" -ForegroundColor White
Write-Host "Total Requests: $totalRequestsSum" -ForegroundColor White
Write-Host "Total Errors: $totalErrorsSum" -ForegroundColor White
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
    $activeResourcesList | Format-Table ResourceName, TotalTokens, TotalRequests, SuccessRate -AutoSize
} else {
    Write-Host "`n⚠️  No resources show token usage in the last $DaysBack days." -ForegroundColor Yellow
    Write-Host "Consider extending the time range or checking if resources have been actively used." -ForegroundColor Yellow
}

Write-Host "`n✅ Metrics collection completed!" -ForegroundColor Green