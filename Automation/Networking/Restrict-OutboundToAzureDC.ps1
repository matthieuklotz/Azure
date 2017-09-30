#
# UpdateNSG.ps1
# Precondition : Register for Augmented Rules
# Register-AzureRmProviderFeature -FeatureName "AllowAccessRuleExtendedProperties" -ProviderNamespace "Microsoft.Network"



workflow Update-NSG-AzureOutbound {
	inlineScript {
		$connectionName = "AzureRunAsConnection"
		try
		{
    		$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName         	
    		Add-AzureRmAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
		}
		catch {
    		if (!$servicePrincipalConnection)
    		{
        		$ErrorMessage = "Connection $connectionName not found."
        		throw $ErrorMessage
    		} else{
        		Write-Error -Message $_.Exception
        		throw $_.Exception
    		}
		}
		
		"Downloading Azure IPs"
		$downloadUri = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"
		$downloadPage = Invoke-WebRequest -Uri $downloadUri -UseBasicParsing
		$xmlFileUri = ($downloadPage.RawContent.Split('"') -like "https://*PublicIps*")[0]
		$response = Invoke-WebRequest -Uri $xmlFileUri -UseBasicParsing
		# Get list of regions & public IP ranges
		[xml]$xmlResponse = [System.Text.Encoding]::UTF8.GetString($response.Content)

		$allowedRegions = (Get-AutomationVariable -Name "AllowOutbound_Regions" -ErrorAction Stop).Split(',')
		$regions = $xmlResponse.AzurePublicIpAddresses.Region | Where-Object { $_.Name -in $allowedRegions  }
		$subscriptions = Get-AzureRmSubscription | Where-Object { $_.State -eq "Enabled" }

		foreach($subscription in $subscriptions)
		{
			"Update NSGs on Subscription $subscription"
			Select-AzureRmSubscription -SubscriptionId $subscription.Id
			$networkSecurityGroups = Get-AzureRmNetworkSecurityGroup
			foreach($nsg in $networkSecurityGroups)
			{
				"Updating NSG " + $nsg.Name 
				$azureRules = $nsg.SecurityRules | Where-Object { $_.Name -like "Allow_Outbound_Azure_*" }
				foreach($azureRule in $azureRules)
				{
					$nsg.SecurityRules.Remove($azureRule)
				}

			    $rulePriority = 100
				foreach($region in $regions)
				{
					$name = "Allow_Outbound_Azure_" + $region.Name
					$rule = New-AzureRmNetworkSecurityRuleConfig -Name $name `
           						-Access Allow `
           						-Protocol * `
           						-Direction Outbound `
           						-Priority $rulePriority `
           						-SourceAddressPrefix VirtualNetwork `
           						-SourcePortRange * `
           						-DestinationAddressPrefix $region.IpRange.Subnet `
           						-DestinationPortRange *
					$nsg.SecurityRules.Add($rule)
					$rulePriority = $rulePriority + 10
				}

				$denyInternetRule = $nsg.SecurityRules | Where-Object { $_.Name -like "Deny_Internet" }
				if($denyInternetRule.Length -eq 0)
				{
					$denyInternetRule = New-AzureRmNetworkSecurityRuleConfig -Name "Deny_Internet" `
           						-Access Deny `
           						-Protocol * `
           						-Direction Outbound `
           						-Priority 4000 `
           						-SourceAddressPrefix VirtualNetwork `
           						-SourcePortRange * `
           						-DestinationAddressPrefix Internet `
           						-DestinationPortRange *
					$nsg.SecurityRules.Add($denyInternetRule)
				}

				Set-AzureRmNetworkSecurityGroup -NetworkSecurityGroup $nsg
			}
		}
	}
}